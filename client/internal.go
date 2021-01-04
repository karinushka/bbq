package client

import (
	"bbq/client/proto"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/kpango/glg"
)

type Stream struct {
	size   uint32
	reader *bufio.Reader
}

func (s *Stream) Peek(i int) ([]byte, error) {
	return s.reader.Peek(i)
}

func (s *Stream) Remaining() uint32 {
	return s.size
}

func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err == nil && s.size >= uint32(n) {
		s.size -= uint32(n)
	}
	return n, err
}

type blockIndex struct {
	Index  proto.FileBlockIndex
	Sizes  []int64
	Blocks []proto.FileBlockIndexEntry
}

func (b *BoxBackup) readBlockIndex(rd *Stream) *blockIndex {
	idx := &blockIndex{}
	binary.Read(rd, binary.BigEndian, &idx.Index)
	glg.Debugf("Magic: %X, file_BlockIndexHeader: %+v", idx.Index.MagicValue, idx.Index)
	l := idx.Index.NumBlocks

	idx.Sizes = make([]int64, l)
	idx.Blocks = make([]proto.FileBlockIndexEntry, l)

	for i := int64(0); i < l; i++ {
		binary.Read(rd, binary.BigEndian, &idx.Sizes[i])

		ent := make([]byte, binary.Size(idx.Blocks[0]))
		rd.Read(ent)
		b.crypt.DecryptBlockIndexEntry(ent, idx.Index.EntryIVBase[:])

		er := bytes.NewReader(ent)
		binary.Read(er, binary.BigEndian, &idx.Blocks[i])
	}
	glg.Logf("read index: %+v", idx)
	return idx
}

func (b *BoxBackup) readFilenameStream(rd *Stream) (string, error) {
	var fl uint16
	binary.Read(rd, binary.LittleEndian, &fl)
	glg.Infof("raw filenamesize: %X", fl)
	enc := fl & 0x3
	fl = fl>>2 - 2 // First two bytes are the length
	glg.Debugf("filenamesize: %v, encoding: %v", fl, enc)

	fn := make([]byte, fl)
	rd.Read(fn)
	glg.Debugf("file: % X", fn)

	fn, err := b.crypt.DecryptFilename(fn)
	if err != nil {
		return "", err
	}
	glg.Debugf("decrypted filename: %s [% X]", fn, fn)
	return string(fn), nil
}

func (b *BoxBackup) writeFilename(fn string) ([]byte, error) {
	ef, err := b.crypt.EncryptFilename([]byte(fn))
	if err != nil {
		return nil, err
	}
	var h uint16
	h = uint16(binary.Size(h) + len(ef))
	buf := make([]byte, h)

	// Filename header is in LittleEndian format already and
	// the lower two bits specify the encoding:
	//	0x01 cleartext
	//	0x02 blowfish.
	h = h<<2 | 0x02
	buf[0] = byte(h & 0xFF)
	buf[1] = byte((h >> 8) & 0xFF)
	copy(buf[2:], ef)
	glg.Debugf("Encoded filename: % X", buf)
	return buf, nil
}

func (b *BoxBackup) readAttributes(rd *Stream, rf *RemoteFile) error {

	var skip []byte
	for {
		p, err := rd.reader.Peek(4)
		if err != nil {
			return err
		}
		if binary.BigEndian.Uint32(p) < rd.size {
			break
		}
		if sb, err := rd.reader.ReadByte(); err != nil {
			return err
		} else {
			skip = append(skip, sb)
		}
		p, err = rd.reader.Peek(4)
	}
	if len(skip) > 0 {
		glg.Warnf("Skipping bytes before attributes: % X\nFile: %+v", skip, rf)
	}

	var s int32 // Attributes size
	binary.Read(rd, binary.BigEndian, &s)
	glg.Infof("attributes size: %v [% X]", s, s)
	if s > 0 {
		var enc uint8
		binary.Read(rd, binary.BigEndian, &enc)
		if enc != 2 {
			return fmt.Errorf("unknown attribute encoding method: %v", enc)
		}

		a := make([]byte, s-1)
		io.ReadFull(rd, a)
		//glg.Logf("attributes: % X", a)
		ab, err := b.crypt.DecryptAttributes(a)
		if err != nil {
			return fmt.Errorf("decrypting attributes: %v", err)
		}

		ar := bytes.NewReader(ab)
		var at proto.AttributeStream
		binary.Read(ar, binary.BigEndian, &at)
		glg.Debugf("decoded attributes: %+v, mode: %o", at, at.Mode)
		if at.AttributeType != 1 { // ATTRIBUTETYPE_GENERIC_UNIX
			return fmt.Errorf("unknown attribute encoding method: %v", at.AttributeType)
		}
		if ar.Len() > 0 {
			glg.Warnf("leftover attributes: %v [% X]", ar.Len(), ab[len(ab)-ar.Len():])
		}
		// TODO: check for following symlinks or xattrs

		rf.UID = at.UID
		rf.GID = at.GID
		rf.ModificationTime = time.Unix(int64(at.ModificationTime/1e6), 0)
		rf.AttributesModTime = time.Unix(int64(at.AttrModificationTime/1e6), 0)
		rf.FileGenerationNumber = at.FileGenerationNumber
		rf.mode = at.Mode

		return nil
	}
	return nil
}

func (b *BoxBackup) readDirStream(rd *Stream) ([]*RemoteFile, error) {
	var ds proto.DirStream
	binary.Read(rd, binary.BigEndian, &ds)
	glg.Debugf("dir: %+v", ds)
        if ds.OptionsPresent != 0 {
            glg.Warnf("Options detected: %+v", ds)
        }

	rf := &RemoteFile{
		ParentId:          ds.ContainerID,
		AttributesModTime: time.Unix(int64(ds.AttributesModTime/1e6), 0),
	}

	if err := b.readAttributes(rd, rf); err != nil {
		return nil, err
	}

	for i := 0; i < int(ds.NumEntries); i++ {
		var e proto.EntryStream
		binary.Read(rd, binary.BigEndian, &e)
		glg.Debugf("entry: %+v", e)

		fn, err := b.readFilenameStream(rd)
		if err != nil {
			return nil, err
		}
		glg.Infof("decrypted filename: % X", fn)
                /*
                if len(fn) == 0 {
                    bb := make([]byte, 5)
                    rd.Read(bb)
                    glg.Warnf("Trying to skip past: % X", bb)
                }
                */
		f := &RemoteFile{
			name:             fn,
			Id:               e.ObjectID,
			ParentId:         ds.ObjectID,
			ModificationTime: time.Unix(int64(e.ModificationTime/1000000), 0),
			size:             e.SizeInBlocks,
			Flags:            e.Flags,
		}
		if err := b.readAttributes(rd, f); err != nil {
			return nil, err
		}
		rf.entries = append(rf.entries, f)
	}

	// TODO: handle symbolic link filenames and xattrs.
	return rf.entries, nil
}

func (b *BoxBackup) readFileStream(rd *Stream, idx *blockIndex) {
	var fs proto.FileStreamFormat
	binary.Read(rd, binary.BigEndian, &fs)
	glg.Debugf("file stream: %+v", fs)

	f := &RemoteFile{
		size:             fs.NumBlocks,
		ParentId:         fs.ContainerID,
		ModificationTime: time.Unix(int64(fs.ModificationTime/1e6), 0),
		// AttributesModTime = time.Unix(int64(at.AttrModificationTime/1e6), 0)
	}
	if fn, err := b.readFilenameStream(rd); err != nil {
		f.name = fn
	}
	b.readAttributes(rd, f)

	var preread []byte
	prep := int64(0)
	if idx == nil {
		// Stream is in file order, so the block index is appended at the end.
		// Read the whole file first to reach the index.
		idxsize := int64(
			binary.Size(proto.FileBlockIndex{}) +
				int(fs.NumBlocks)*(8+binary.Size(proto.FileBlockIndexEntry{})))
		// Size of the file data is: total - index size
		glg.Debugf("file data: %v, index size %v", rd.Remaining(), idxsize)
		preread = make([]byte, int64(rd.Remaining())-idxsize)
		io.ReadFull(rd, preread)

		idx = b.readBlockIndex(rd)
	}

	for i, ent := range idx.Blocks {
		bs := idx.Sizes[i]
		if bs < 0 {
			// TODO: check for blocks from other files
			glg.Warnf("Detected reference to a foreign block: %v", bs)
		}
		glg.Debugf("processing entry: bs: %v, %+v", bs, ent)

		var buf []byte
		if len(preread) > 0 {
			buf = preread[prep : prep+bs]
			prep += bs
		} else {
			buf = make([]byte, bs)
			io.ReadFull(rd, buf)
		}

		compressed := 1 == (buf[0] & 1)
		encoder := buf[0] >> 1
		glg.Debugf("chunk compresed?: %v", compressed)
		glg.Debugf("chunk encoder: %v", encoder)

		ct, err := b.crypt.DecryptFileData(buf[1:])
		if err != nil {
			return
		}

		glg.Logf("Decoded size: %v", ent.Size)
		if compressed {
			glg.Debugf("Compressed header: % X", ct[0:10])
			out := make([]byte, ent.Size)
			if nil != b.crypt.Decompress(ct, out) {
				glg.Errorf("decompression error: %v", err)
				continue
			}
			glg.Debugf("actual decompressed: %s", out[0:20])

			// TODO: verify checksum

		} else {
			glg.Infof("Decoded: %s", ct)
		}
	}
}

func (b *BoxBackup) readStream() ([]*RemoteFile, error) {
	s, err := b.GetStream()
	if err != nil {
		return nil, err
	}
	p, err := s.Peek(4)
	if err != nil {
		return nil, err
	}
	switch m := string(p); m {
	case "file":
		// File coming in store format, block index at the end.
		b.readFileStream(s, nil)

	case "bidx":
		// File coming in stream format, block index first.
		idx := b.readBlockIndex(s)
		b.readFileStream(s, idx)

	case "DIR_":
		return b.readDirStream(s)

	default:
		return nil, fmt.Errorf("unknown stream magic: %s", m)
	}

	if s.Remaining() > 0 {
		// Rest of the stream
		r := make([]byte, s.Remaining())
		io.ReadFull(s, r)
		glg.Warnf("Stream not fully read: % X", r)
	}
	return nil, nil
}
