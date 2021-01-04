package client

import (
	"bbq/client/proto"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kpango/glg"
)

// RemoteFile structure implements os.FileInfo interface.
type RemoteFile struct {
	name                 string
	Id                   int64
	ParentId             int64
	size                 int64
	UID                  uint32
	GID                  uint32
	mode                 uint16
	Flags                int16
	ModificationTime     time.Time
	AttributesModTime    time.Time
	FileGenerationNumber uint32

	entries []*RemoteFile

	remote     *Stream
	fileStream proto.FileStreamFormat

	idx       *blockIndex
	curBlock  int64
	block     []byte
	blockLeft int

	boxBackup *BoxBackup
}

// Base name of the file
func (f *RemoteFile) Name() string {
	return f.name
}

// length in bytes for regular files; system-dependent for others
func (f *RemoteFile) Size() int64 {
	return f.size
}

// file mode bits
func (f *RemoteFile) Mode() os.FileMode {
	m := os.FileMode(f.mode)
	if f.Flags&2 > 0 {
		m |= os.ModeDir
	}
	return m
}

// modification time
func (f *RemoteFile) ModTime() time.Time {
	return f.ModificationTime
}

// abbreviation for Mode().IsDir()
func (f *RemoteFile) IsDir() bool {
	return f.Mode().IsDir()
}

// underlying data source (can return nil)
func (f *RemoteFile) Sys() interface{} {
	return nil
}

func (b *BoxBackup) OpenFile(curDir, id int64) (*RemoteFile, error) {
	if _, err := b.Execute(&Operation{Op: proto.GetFile{
		InDirectory: curDir,
		ObjectID:    id,
	}}); err != nil {
		return nil, fmt.Errorf("get file failed: %q", err)
	}

	rd, err := b.GetStream()
	if err != nil {
		return nil, fmt.Errorf("unale to read stream: %q", err)
	}
	f := &RemoteFile{
		boxBackup: b,
		remote:    rd,
		idx:       b.readBlockIndex(rd),
	}

	if err := binary.Read(rd, binary.BigEndian, &f.fileStream); err != nil {
		glg.Errorf("Error opening: %v", err)
		return nil, fmt.Errorf("open: %v", err)
	}
	glg.Debugf("file stream: %+v", f.fileStream)
	f.size = f.fileStream.NumBlocks
	f.ModificationTime = time.Unix(int64(f.fileStream.ModificationTime/1e6), 0)

	if n, err := b.readFilenameStream(rd); err != nil {
		glg.Errorf("Error reading filename: %v", err)
		return nil, fmt.Errorf("read filename: %v", err)
	} else {
		f.name = n
	}

	if err := b.readAttributes(rd, f); err != nil {
		glg.Errorf("Error reading attributes: %v", err)
		return nil, fmt.Errorf("read attributes: %v", err)
	}

	return f, nil
}

func (f *RemoteFile) Close() error {
	// flush remaining stream
	b := make([]byte, 4096)
	for i := int(f.remote.Remaining()); i > 0; {
		n, err := f.remote.Read(b)
		if err != nil {
			glg.Errorf("error closing: %s", err)
			return err
		}
		i -= n
	}
	return nil
}

func (f *RemoteFile) Read(p []byte) (int, error) {
	var i int
	for i < len(p) {

		if f.blockLeft < len(f.block) {
			// There's some data left over in the buffer from previous block.
			c := copy(p[i:], f.block[f.blockLeft:])
			f.blockLeft += c
			i += c
			continue
		}

		if f.curBlock >= f.idx.Index.NumBlocks {
			return i, io.EOF
		}

		s := f.idx.Sizes[f.curBlock]
		blk := f.idx.Blocks[f.curBlock]

		if s < 0 {
			// TODO: check for blocks from other files
			glg.Warnf("Detected reference to a foreign block: %v", s)
		}
		glg.Debugf("processing block of size: %v, %+v", s, blk)

		buf := make([]byte, s)
		io.ReadFull(f.remote, buf)

		compressed := 1 == (buf[0] & 1)
		encoder := buf[0] >> 1
		glg.Debugf("chunk compresed?: %v", compressed)
		glg.Debugf("chunk encoder: %v", encoder)

		dec, err := f.boxBackup.crypt.DecryptFileData(buf[1:])
		if err != nil {
			glg.Errorf("decrypting file: %v", err)
			return 0, err
		}

		glg.Logf("Decoded size: %v", blk.Size)
		if compressed {
			f.block = make([]byte, blk.Size)
			if nil != f.boxBackup.crypt.Decompress(dec, f.block) {
				glg.Errorf("decompression error: %v", err)
				return 0, fmt.Errorf("decompression error: %v", err)
			}
			glg.Debugf("actual decompressed: %s", f.block[0:20])

		} else {
			f.block = dec
		}

		if md5.Sum(f.block) != blk.StrongChecksum {
			glg.Fatalf("MD5 checksum failed for block %v in file %v (0x%x)", f.curBlock, f.name, f.Id)
			return i, fmt.Errorf("MD5 checksum failed for block %v in file %v (0x%x)",
				f.curBlock, f.name, f.Id)
		}

		f.blockLeft = 0
		f.curBlock++
	}
	return i, nil
}
