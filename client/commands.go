package client

import (
	"bbq/client/proto"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/kpango/glg"
)

func (b *BoxBackup) CheckVersion(version int32) error {
	p, err := b.Execute(&Operation{Op: proto.Version{Version: version}})
	if err != nil {
		return fmt.Errorf("version check failed: %q", err)
	}
	glg.Logf("server version: %v", p.(*proto.Version).Version)
	return nil
}

func (b *BoxBackup) Login(user int32, ro bool) error {
	f := int32(0)
	if ro {
		f = f | 1
	}
	p, err := b.Execute(&Operation{Op: proto.Login{
		Client: user,
		Flags:  f,
	}})
	if err != nil {
		return fmt.Errorf("login failed: %q", err)
	}
	glg.Logf("logged in: %+v", p.(*proto.LoginConfirmed))
	return nil
}

func (b *BoxBackup) Finish() error {
	_, err := b.Execute(&Operation{Op: proto.Finished{}})
	glg.Log("logged out")
	return err
}

func (b *BoxBackup) ReadDir(id int64) ([]*RemoteFile, error) {
	p, err := b.Execute(&Operation{Op: proto.ListDirectory{
		ObjectID:        id,
		FlagsMustBeSet:  -1,
		FlagsNotToBeSet: 0,
		// TODO: do the attributes things here
		SendAttributes: true,
	}})
	if err != nil {
		return nil, fmt.Errorf("lsdir failed: %q", err)
	}
	glg.Logf("list directory: %v", p.(*proto.Success).ObjectID)

	return b.readStream()
}

func (b *BoxBackup) GetObjectName(d, id int64) ([]string, error) {
	p, err := b.Execute(&Operation{Op: proto.GetObjectName{
		ObjectID:              id,
		ContainingDirectoryID: d,
	}})
	if err != nil {
		return nil, fmt.Errorf("get object name failed: %q", err)
	}
	o := p.(*proto.ObjectName)
	if o.NumNameElements == 0 {
		return nil, fmt.Errorf("can not find object name id %v in %v", id, d)
	}
	glg.Logf("get object name: %+v", o)

	// Returns a stream of filename objects - a directory path.
	s, err := b.GetStream()
	if err != nil {
		return nil, err
	}
	var path []string
	for i := 0; i < int(o.NumNameElements); i++ {
		fn, err := b.readFilenameStream(s)
		if err != nil {
			return nil, err
		}
		path = append(path, fn)
	}
	return path, nil
}

func (b *BoxBackup) GetAccountUsage() error {
	p, err := b.Execute(&Operation{Op: proto.GetAccountUsage2{}})
	if err != nil {
		return fmt.Errorf("get account usage failed: %q", err)
	}
	glg.Logf("account usage: %+v", p.(*proto.AccountUsage2))
	return nil
}

func (b *BoxBackup) GetFile(d, id int64) (*RemoteFile, error) {
	rf, err := b.OpenFile(d, id)
	if err != nil {
		return nil, err
	}
	var buf [1024]byte
	for r, err := rf.Read(buf[:]); err == nil && r == len(buf); {
		r, err = rf.Read(buf[:])
	}
	rf.Close()
	return rf, nil
}

func (b *BoxBackup) GetObject(id int64) (*RemoteFile, error) {
	_, err := b.Execute(&Operation{Op: proto.GetObject{
		ObjectID: id,
	}})
	if err != nil {
		return nil, fmt.Errorf("get object failed: %q", err)
	}
	f, err := b.readStream()
	if err != nil {
		return nil, err
	}
	if len(f) > 0 {
		return f[0], nil
	}
	return nil, nil
}

func (b *BoxBackup) GetBlockIndexByID(id int64) error {
	_, err := b.Execute(&Operation{Op: proto.GetBlockIndexByID{
		ObjectID: id,
	}})
	if err != nil {
		return fmt.Errorf("get index by id failed: %q", err)
	}
	s, err := b.GetStream()
	if err != nil {
		return err
	}
	glg.Logf("stream with blocks: %+v", s)
	b.readBlockIndex(s)
	return nil
}

func (b *BoxBackup) GetBlockIndexByName(d int64, fn string) error {
	ef, err := b.writeFilename(fn)
	if err != nil {
		return err
	}
	op := &Operation{
		Op: proto.GetBlockIndexByName{
			InDirectory: d,
		},
		Tail: ef,
	}
	p, err := b.Execute(op)
	if err != nil {
		return fmt.Errorf("get index by name failed: %q", err)
	}

	if p.(*proto.Success).ObjectID == 0 {
		return fmt.Errorf("file %s not found", fn)
	}
	s, err := b.GetStream()
	if err != nil {
		return err
	}
	glg.Logf("stream with blocks: %+v", s)
	b.readBlockIndex(s)
	return nil
}

func (b *BoxBackup) DeleteFile(d int64, fn string) error {
	ef, err := b.writeFilename(fn)
	glg.Logf("Delete %s [% X] / [% X]", fn, fn, ef)
	if err != nil {
		return err
	}
	op := &Operation{
		Op: proto.DeleteFile{
			InDirectory: d,
		},
		Tail: ef,
	}
	p, err := b.Execute(op)
	if err != nil {
		return fmt.Errorf("delete file failed: %q", err)
	}
	if p.(*proto.Success).ObjectID == 0 {
		return fmt.Errorf("file %s was not found", fn)
	}
	return nil
}

func (b *BoxBackup) StoreFile(d, m, a int64, fn string, fc []byte) error {
	// First prepare the file stream
	buf := new(bytes.Buffer)

	fs := proto.FileStreamFormat{
		MagicValue:        0x66696C65,
		NumBlocks:         1,
		ContainerID:       d,
		ModificationTime:  0,
		MaxBlockClearSize: 0,
		Options:           0,
	}
	binary.Write(buf, binary.BigEndian, &fs)

	// Filename
	ef, _ := b.writeFilename(fn)
	buf.Write(ef)

	// Attribute block
	if err := b.writeAttributes(buf, &RemoteFile{}); err != nil {
		return err
	}

	// Send the file data right away, as in Storage format.
	// Block index will come trailing
	var bh uint8 = 0b10
	binary.Write(buf, binary.BigEndian, &bh)

	iv := make([]byte, 16)
	rand.Read(iv)
	ct, err := b.crypt.EncryptFileData(fc, iv)
	if err != nil {
		return err
	}
	buf.Write(ct)

	// Block Index
	bi := blockIndex{
		Index: proto.FileBlockIndex{
			MagicValue:  0x62696478,
			OtherFileID: 0,
			NumBlocks:   1,
		},
	}
	rand.Read(bi.Index.EntryIVBase[:])

	// Length of this fileblock including the byte header
	bi.Sizes = append(bi.Sizes, int64(len(ct)+1))
	bi.Blocks = append(bi.Blocks, proto.FileBlockIndexEntry{
		Size:           int32(len(fc)), // decrypted size
		WeakChecksum:   calcRollingChecksum(fc),
		StrongChecksum: md5.Sum(fc),
	})
	b.writeBlockIndex(buf, &bi)

	_, err = b.Execute(&Operation{
		Op: proto.StoreFile{
			DirectoryObjectID: d,
			ModificationTime:  m,
			AttributesHash:    a,
			DiffFromFileID:    0, // 0 if the file is not a diff
		},
		Tail:   ef,
		Stream: buf,
	})
	if err != nil {
		return fmt.Errorf("get file failed: %q", err)
	}
	return nil
}
