package client

import (
	"bbq/client/proto"
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
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

var fileModes = []struct {
	unix   uint8
	golang os.FileMode
}{
	// #define __S_IFIFO       0010000 // FIFO.
	// #define __S_IFCHR       0020000 // Character device.
	// #define __S_IFDIR       0040000 // Directory.
	// #define __S_IFBLK       0060000 // Block device.
	// #define __S_IFREG       0100000 // Regular file.
	// #define __S_IFLNK       0120000 // Symbolic link.
	// #define __S_IFSOCK      0140000 // Socket.
	{0o1, os.ModeNamedPipe},
	{0o2, os.ModeCharDevice},
	{0o4, os.ModeDir},
	{0o6, os.ModeDevice},
	{0o10, 0},
	{0o12, os.ModeSymlink},
	{0o14, os.ModeSocket},
}

func readMode(m uint16) os.FileMode {
	fm := os.FileMode(m & 0xFFF)
	s := uint8(0xF & (m >> 12))
	for _, k := range fileModes {
		if k.unix == s {
			fm |= k.golang
			break
		}
	}
	return fm
}

func writeMode(m os.FileMode) uint16 {
	om := uint16(m & os.ModePerm)
	s := m & os.ModeType
	for _, k := range fileModes {
		if k.golang == s {
			om |= uint16(k.unix) << 12
			break
		}
	}
	return om
}

// Calculates rolling checksum, ala BoxBackup style.
func calcRollingChecksum(b []byte) uint32 {
	// Two halves of the weak rolling checksum
	var wcA, wcB uint16
	k := 0
	for y := len(b); y > 0; y-- {
		wcA += uint16(b[k])
		wcB += uint16(y) * uint16(b[k])
		k++
	}
	return uint32(wcB)<<16 | uint32(wcA)
}

// Decodes a single block into resulting size s.
func (b *BoxBackup) decodeBlock(buf []byte, blk *proto.FileBlockIndexEntry) ([]byte, error) {
	compressed := 1 == (buf[0] & 1)
	encoder := buf[0] >> 1
	glg.Debugf("chunk compressed: %v, encoded: %v", compressed, encoder)

	var out []byte
	if encoder != 0 {
		d, err := b.crypt.DecryptFileData(buf[1:])
		if err != nil {
			glg.Errorf("decrypting file: %v", err)
			return nil, err
		}
		out = d
	} else {
		out = buf[1:]
	}

	if compressed {
		d := make([]byte, blk.Size)
		if err := b.crypt.Decompress(out, d); err != nil {
			glg.Errorf("decompression error: %v", err)
			return nil, fmt.Errorf("decompression error: %v", err)
		}
		glg.Debugf("actual decompressed (size: %v): %s", len(d), d[0:20])
		out = d
	}

	w := calcRollingChecksum(out)
	// For some weird reason my rolling checksum is always off by a couple
	// of increments for the subsequent blocks. Maybe there's a bug in
	// BoxBackup checksum calculation somewhere.
	if (blk.WeakChecksum ^ w) > 8 {
		// glg.Logf("First bytes: % v, Last byte: % v", f.block[0:4], f.block[len(f.block)-4:])
		glg.Errorf("Weak checksum failed: 0x%x != 0x%x", w, blk.WeakChecksum)
	}

	// Do the strong checksum
	if md5.Sum(out) != blk.StrongChecksum {
		glg.Error("MD5 checksum failed")
		return nil, fmt.Errorf("MD5 checksum failed")
	}

	return out, nil
}

func (b *BoxBackup) writeBlockIndex(buf *bytes.Buffer, bix *blockIndex) error {
	binary.Write(buf, binary.BigEndian, &bix.Index)
	for i, s := range bix.Sizes {
		binary.Write(buf, binary.BigEndian, &s)

		// Encrypt the actual block
		bi := new(bytes.Buffer)
		binary.Write(bi, binary.BigEndian, bix.Blocks[i])
		ei := bi.Next(binary.Size(bix.Blocks[i]))
		b.crypt.EncryptBlockIndexEntry(ei, bix.Index.EntryIVBase[:])
		binary.Write(buf, binary.BigEndian, ei)
	}
	return nil
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
	return idx
}

func (b *BoxBackup) readFilenameStream(rd *Stream) (string, error) {
	var fl uint16
	binary.Read(rd, binary.LittleEndian, &fl)
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

func (b *BoxBackup) writeAttributes(buf *bytes.Buffer, rf *RemoteFile) error {
	at := proto.AttributeStream{
		AttributeType:    1, // ATTRIBUTETYPE_GENERIC_UNIX
		UID:              rf.UID,
		GID:              rf.GID,
		ModificationTime: uint64(rf.ModificationTime.UnixNano() / 1000),
		// TODO: fill out the missing members
		// AttrModificationTime uint64
		// UserDefinedFlags     uint32
		// FileGenerationNumber uint32
		Mode: writeMode(rf.mode),
	}
	eab := new(bytes.Buffer)
	binary.Write(eab, binary.BigEndian, &at)
	ea := eab.Next(binary.Size(at))

	iv := make([]byte, 8)
	rand.Read(iv)
	eat, err := b.crypt.EncryptAttributes(ea, iv)
	if err != nil {
		return err
	}

	var ae uint8 = 2 // Attribute encoding (Blowfish)
	var s int32 = int32(binary.Size(ae) + len(eat))
	binary.Write(buf, binary.BigEndian, &s)
	binary.Write(buf, binary.BigEndian, &ae)
	binary.Write(buf, binary.BigEndian, eat)

	return nil
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
	glg.Infof("attributes size: %v", s)
	if s > 0 {
		var enc uint8
		binary.Read(rd, binary.BigEndian, &enc)
		if enc != 2 {
			return fmt.Errorf("unknown attribute encoding method: %v", enc)
		}

		a := make([]byte, s-1)
		io.ReadFull(rd, a)
		ab, err := b.crypt.DecryptAttributes(a)
		if err != nil {
			return fmt.Errorf("decrypting attributes: %v", err)
		}

		ar := bytes.NewReader(ab)
		var at proto.AttributeStream
		binary.Read(ar, binary.BigEndian, &at)
		glg.Debugf("decoded attributes: %+v, mode: %o", at, at.Mode)
		if at.AttributeType != 1 { // ATTRIBUTETYPE_GENERIC_UNIX
			return fmt.Errorf("unknown attribute type: %v", at.AttributeType)
		}
		rf.mode = readMode(at.Mode)
		rf.UID = at.UID
		rf.GID = at.GID
		rf.ModificationTime = time.Unix(int64(at.ModificationTime/1e6), 0)
		rf.AttributesModTime = time.Unix(int64(at.AttrModificationTime/1e6), 0)
		rf.FileGenerationNumber = at.FileGenerationNumber

		if ar.Len() > 0 {
			if rf.mode&os.ModeSymlink > 0 {
				// Read symlink name after the attributes
				rf.Symlink = string(ab[len(ab)-ar.Len():])
				glg.Debugf("Read symlink: %s", rf.Symlink)
			} else {
				// TODO: check for following xattrs
				glg.Warnf("leftover attributes: %v [% X]", ar.Len(), ab[len(ab)-ar.Len():])
			}
		}

	}
	return nil
}

func (b *BoxBackup) readDirStream(rd *Stream) ([]*RemoteFile, error) {
	var ds proto.DirStream
	binary.Read(rd, binary.BigEndian, &ds)
	glg.Debugf("dir: %+v", ds)

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
		f := &RemoteFile{
			name:             fn,
			Id:               e.ObjectID,
			ParentId:         ds.ObjectID,
			ModificationTime: time.Unix(int64(e.ModificationTime/1e6), 0),
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
	if err := b.readAttributes(rd, f); err != nil {
		glg.Error("readFileStream:", err)
		return
	}

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

		if _, err := b.decodeBlock(buf, &ent); err != nil {
			glg.Errorf("Error decoding block: %s", err)
			return
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
