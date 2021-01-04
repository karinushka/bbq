package client

import (
	"bbq/client/proto"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/karinushka/chunker/chunker"
	"github.com/kpango/glg"
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
	mode                 uint16
	Flags                int16
	ModificationTime     time.Time
	AttributesModTime    time.Time
	FileGenerationNumber uint32

	entries []*RemoteFile

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

		// Two halves of the weak rolling checksum
		var wcA, wcB uint16
		k := 0
		for y := len(f.block); y > 0; y-- {
			wcA += uint16(f.block[k])
			wcB += uint16(y) * uint16(f.block[k])
			k++
		}
		w := uint32(wcB)<<16 | uint32(wcA)
		// For some weird reason my rolling checksum is always off by a couple
		// of increments for the subsequent blocks. Maybe there's a bug in
		// BoxBackup checksum calculation somewhere.
		if (blk.WeakChecksum ^ w) > 8 {
			// glg.Logf("First bytes: % v, Last byte: % v", f.block[0:4], f.block[len(f.block)-4:])
			glg.Errorf("Weak checksum failed for block %v in file %v (0x%x) 0x%x != 0x%x", f.curBlock, f.name, f.Id, w, blk.WeakChecksum)
		}

		// Do the strong checksum
		if md5.Sum(f.block) != blk.StrongChecksum {
			glg.Errorf("MD5 checksum failed for block %v in file %v (0x%x)", f.curBlock, f.name, f.Id)
			return i, fmt.Errorf("MD5 checksum failed for block %v in file %v (0x%x)",
				f.curBlock, f.name, f.Id)
		}

		f.blockLeft = 0
		f.curBlock++
	}
	return i, nil
}

func (b *BoxBackup) CreateFile(curDir int64, name string, modTime time.Time, uid, gid uint32) (*RemoteFile, error) {
	// TODO: handle AttributesHash and DiffFromFileID at some point.

	f := &RemoteFile{
		boxBackup: b,
		name:      name,
		// Id                   int64
		ParentId: curDir,
		// size                 int64
		UID:              uid,
		GID:              gid,
		ModificationTime: modTime,
		// TODO: do other fields as well
	}

	var cb chunker.Callback = func(c []byte) error {
		f.chunks = append(f.chunks, c)
		return nil
	}

	key := make([]byte, 32)
	rand.Read(key)
	var mean uint32 = 10240
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
	glg.Info("Write")
	return 0, nil
}

func (f *RemoteFile) Commit() error {
	if err := f.chunkify.End(); err != nil {
		return err
	}
	glg.Infof("chunks: %+v", f.chunks)

	// First prepare the file stream
	b := bytes.NewBuffer([]byte{})
	fs := proto.FileStreamFormat{
		MagicValue:       0x66696C65,
		NumBlocks:        int64(len(f.chunks)),
		ContainerID:      f.ParentId,
		ModificationTime: f.ModificationTime.Unix(),
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

	iv := make([]byte, 16)
	rand.Read(iv)

	// Send the file chunks first, as in Storage format.
	var bh uint8 = 0b10
	for _, ch := range f.chunks {
		binary.Write(b, binary.BigEndian, &bh)

		ct, err := f.boxBackup.crypt.EncryptFileData(ch, iv)
		if err != nil {
			return err
		}
		b.Write(ct)

		// Length of this fileblock including the byte header
		bi.Sizes = append(bi.Sizes, int64(len(ct)+1))
		bie := proto.FileBlockIndexEntry{
			Size: int32(len(ch)), // decrypted size
			// TODO: put proper checksum here
			WeakChecksum:   1,
			StrongChecksum: md5.Sum(ch),
		}
		bi.Blocks = append(bi.Blocks, bie)
	}

	f.boxBackup.writeBlockIndex(b, bi)

	glg.Logf("buf: % X", b)

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
		Stream: []byte(b.String()),
	})
	if err != nil {
		return fmt.Errorf("get file failed: %q", err)
	}
	return nil
}
