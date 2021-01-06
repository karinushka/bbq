package client

import (
	"bbq/client/proto"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kpango/glg"
	"rolling/chunker"
)

// RemoteFile structure implements os.FileInfo interface.
type RemoteFile struct {
	boxBackup *BoxBackup

	name                 string
	Id                   int64
	ParentId             int64
	size                 int64
	UID                  uint32
	GID                  uint32
	mode                 os.FileMode
	Flags                int16
	ModificationTime     time.Time
	AttributesModTime    time.Time
	FileGenerationNumber uint32

	entries []*RemoteFile
	Symlink string

	remote     *Stream
	fileStream proto.FileStreamFormat

	// Reading state
	idx       *blockIndex
	curBlock  int64
	block     []byte
	blockLeft int

	// Writing state
	chunkify *chunker.Chunker
	chunks   [][]byte
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
	m := f.mode
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
		return nil, fmt.Errorf("unable to read stream: %q", err)
	}
	f := &RemoteFile{
		Id:        id,
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

		var err error
		f.block, err = f.boxBackup.decodeBlock(buf, &blk)
		if err != nil {
			return 0, err
		}

		f.blockLeft = 0
		f.curBlock++
	}
	return i, nil
}

func (b *BoxBackup) CreateFile(curDir int64, name string) (*RemoteFile, error) {
	// TODO: handle AttributesHash and DiffFromFileID at some point.

	f := &RemoteFile{
		boxBackup: b,
		name:      name,
		// Id                   int64
		ParentId: curDir,
		// size                 int64
		mode: 1, // File
		// TODO: do other fields as well
	}

	var cb chunker.Callback = func(c []byte) error {
		f.chunks = append(f.chunks, c)
		return nil
	}

	key := make([]byte, 32)
	rand.Read(key)
	var mean uint32 = 8192
	var err error
	if f.chunkify, err = chunker.ChunkifyInit(key, mean, 3*mean, cb); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *RemoteFile) Write(p []byte) (int, error) {
	if err := f.chunkify.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *RemoteFile) Commit() error {
	if err := f.chunkify.End(); err != nil {
		return err
	}

	// First prepare the file stream
	b := new(bytes.Buffer)
	fs := proto.FileStreamFormat{
		MagicValue:       0x66696C65,
		NumBlocks:        int64(len(f.chunks)),
		ContainerID:      f.ParentId,
		ModificationTime: f.ModificationTime.UnixNano() / 1000,
		// TODO: these fields should be set to something
		// MaxBlockClearSize: 0,
		// Options:           0,
	}
	binary.Write(b, binary.BigEndian, &fs)

	// Filename
	ef, err := f.boxBackup.writeFilename(f.name)
	if err != nil {
		return err
	}
	b.Write(ef)

	// Attribute block
	if err := f.boxBackup.writeAttributes(b, f); err != nil {
		return err
	}

	// Block index will come trailing after the file data
	bi := &blockIndex{
		Index: proto.FileBlockIndex{
			MagicValue: 0x62696478,
			// TODO: do this other file ID also.
			OtherFileID: 0,
			NumBlocks:   int64(len(f.chunks)),
		},
	}
	rand.Read(bi.Index.EntryIVBase[:])

	zb := new(bytes.Buffer)
	z := zlib.NewWriter(zb)
	var bh uint8 // Block header

	// Send the file chunks first, as in Storage format.
	for _, ch := range f.chunks {

		bi.Blocks = append(bi.Blocks, proto.FileBlockIndexEntry{
			Size:           int32(len(ch)), // decrypted size
			WeakChecksum:   calcRollingChecksum(ch),
			StrongChecksum: md5.Sum(ch),
		})

		zb.Reset()
		z.Reset(zb)
		w, err := z.Write(ch)
		if err != nil || w < len(ch) {
			return err
		}
		z.Close()

		// Compress only if can get below 95%
		if (100 * zb.Len() / len(ch)) < 95 {
			glg.Debugf("Compressed to: %v%% (%v, %v)", 100*zb.Len()/len(ch), zb.Len(), len(ch))
			ch = zb.Bytes()
			bh = 0b11
		} else {
			bh = 0b10
		}

		iv := make([]byte, 16)
		rand.Read(iv)
		ct, err := f.boxBackup.crypt.EncryptFileData(ch, iv)
		if err != nil {
			return err
		}

		binary.Write(b, binary.BigEndian, &bh)
		b.Write(ct)

		// Length of this fileblock including the byte header
		bi.Sizes = append(bi.Sizes, int64(len(ct)+1))
	}

	f.boxBackup.writeBlockIndex(b, bi)

	_, err = f.boxBackup.Execute(&Operation{
		Op: proto.StoreFile{
			DirectoryObjectID: f.ParentId,
			ModificationTime:  fs.ModificationTime,
			// TODO: handle attribute hashes
			AttributesHash: 0,
			// TODO: handle diff files
			DiffFromFileID: 0, // 0 if the file is not a diff
		},
		Tail:   ef,
		Stream: b,
	})
	if err != nil {
		return fmt.Errorf("get file failed: %q", err)
	}
	return nil
}
