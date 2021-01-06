package client

import (
	"bbq/client/proto"
	"bbq/crypto"
	"io"
	"net"
	"os"
	"testing"

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

	done := make(chan bool)
	go func() {
		if err := bbs.StoreFile(1, 2, 3, "foo", []byte("bar")); err != nil {
			t.Errorf("StoreFile: %s", err)
			return
		}
		glg.Info("Written file")
		s.Close()
		done <- true
	}()

	h := make([]byte, 50)
	io.ReadFull(c, h)
	glg.Infof("Header: % X", h)

	bbc.readStream()
	sendCommand(c, &Operation{Op: proto.Success{}})
	<-done
}

func TestWriteFile(t *testing.T) {
	glg.Get().DisableColor()

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

	w, err := os.Open("file.go")
	if err != nil {
		t.Errorf("Unable to open file: %s", err)
		return
	}
	defer w.Close()

	done := make(chan bool)
	go func() {
		f, err := bbs.CreateFile(3, "test")
		glg.Infof("cr: %+v", f)
		if err != nil {
			t.Errorf("CreateFile: %s", err)
			return
		}
		if _, err := io.Copy(f, w); err != nil {
			t.Errorf("Write Error: %s", err)
			return
		}
		glg.Info("Commiting")
		if err := f.Commit(); err != nil {
			t.Errorf("Commit: %s", err)
			return
		}
		glg.Info("Created file")
		s.Close()
		done <- true
	}()

	h := make([]byte, 50)
	io.ReadFull(c, h)
	glg.Infof("Header: % X", h)

	bbc.readStream()
	sendCommand(c, &Operation{Op: proto.Success{}})
	<-done
}
