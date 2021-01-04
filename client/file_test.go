package client

import (
	"bbq/crypto"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kpango/glg"
)

func TestStoreFile(t *testing.T) {
	cr, err := crypto.NewCrypto("../1-FileEncKeys.raw")
	if err != nil {
		t.Errorf("Unable to load crypto")
		return
	}

	s, c := net.Pipe()
	bbs := NewBoxBackup(s, cr)
	bbs.ready = true
	bbc := NewBoxBackup(c, cr)
	bbc.ready = true

	go func() {
		if err := bbs.StoreFile(1, 2, 3, "foo", []byte("bar")); err != nil {
			t.Errorf("StoreFile: %s", err)
			return
		}
		glg.Info("Written file")
		s.Close()
	}()

	h := make([]byte, 50)
	io.ReadFull(c, h)
	glg.Infof("Header: % X", h)

	bbc.readStream()
}

func TestWriteFile(t *testing.T) {
	cr, err := crypto.NewCrypto("../1-FileEncKeys.raw")
	if err != nil {
		t.Errorf("Unable to load crypto")
		return
	}

	s, c := net.Pipe()
	bbs := NewBoxBackup(s, cr)
	bbs.ready = true
	bbc := NewBoxBackup(c, cr)
	bbc.ready = true

	go func() {
		f, err := bbs.CreateFile(3, "test", time.Now(), 101, 100)
		glg.Infof("cr: %+v", f)
		if err != nil {
			t.Errorf("CreateFile: %s", err)
			return
		}
		if _, err := f.Write([]byte("testing 123")); err != nil {
			t.Errorf("Write: %s", err)
			return
		}
		if err := f.Commit(); err != nil {
			t.Errorf("Commit: %s", err)
			return
		}
		glg.Info("Created file")
		s.Close()
	}()

	h := make([]byte, 50)
	io.ReadFull(c, h)
	glg.Infof("Header: % X", h)

	bbc.readStream()
}
