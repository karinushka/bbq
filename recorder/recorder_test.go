package main

import (
	"bbq/client"
	"bbq/crypto"
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kpango/glg"
)

type MockStoreServer struct {
	net.Conn
	test       *testing.T
	recv, send *bytes.Reader
}

func (s *MockStoreServer) Read(p []byte) (int, error) {
	// glg.Infof("REPLAY: reading %v bytes", len(p))
	if _, err := s.recv.Read(p); err != nil {
		s.test.Errorf("Ran out of recv material")
	}
	return len(p), nil
}
func (s *MockStoreServer) Write(p []byte) (int, error) {
	// glg.Infof("REPLAY: writing %v bytes", len(p))
	c := make([]byte, len(p))

	if len(p) == 0 {
		glg.Warn("Empty write")
		return 0, nil
	}

	if _, err := s.send.Read(c); err != nil {
		s.test.Errorf("Ran out of send material")
		return 0, fmt.Errorf("Ran out of send material")
	}
	if bytes.Compare(c, p) != 0 {
		s.test.Errorf("Invalid write replay: % X instead of % X", c, p)
		return 0, fmt.Errorf("Invalid write: expected [% X] but got [% X]", c, p)
	}
	return len(c), nil
}

func (s *MockStoreServer) PrintBuffers() {
	glg.Logf("REPLAY: recv: %v bytes", s.recv.Len())
	glg.Logf("REPLAY: send: %v bytes", s.send.Len())
}

func (s *MockStoreServer) loadBuffer(n string) (*bytes.Reader, error) {
	f, err := os.Open(n)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var b []uint8
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Text()) > 0 {
			for _, c := range strings.Split(sc.Text(), " ") {
				if i, err := strconv.ParseUint(c, 16, 8); err == nil {
					b = append(b, uint8(i))
				} else {
					return nil, err
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		s.test.Errorf("failed to read: %s", err)
	}
	return bytes.NewReader(b), nil
}

func (s *MockStoreServer) LoadBuffers(n string) error {
	b, err := s.loadBuffer("w-" + n)
	if err != nil {
		return err
	}
	s.send = b
	// glg.Infof("REPLAY: loaded send: % X", b)
	b, err = s.loadBuffer("r-" + n)
	if err != nil {
		return err
	}
	s.recv = b
	// glg.Infof("REPLAY: loaded recv: % X", b)
	return nil
}

func NewMockStoreServer(t *testing.T) *MockStoreServer {
	s := &MockStoreServer{
		test: t,
	}
	return s
}

func initServer(t *testing.T) (*MockStoreServer, *client.BoxBackup) {

	cr, err := crypto.NewCrypto("../1-FileEncKeys.raw")
	if err != nil {
		t.Errorf("Unable to load crypto")
		return nil, nil
	}

	s := NewMockStoreServer(t)
	bb := client.NewBoxBackup(s, cr)

	s.LoadBuffers("login.txt")
	if err := bb.CheckVersion(1); err != nil {
		glg.Error(err)
	}
	if err := bb.Login(1, false); err != nil {
		glg.Error(err)
	}

	return s, bb
}

func TestGetAccountUsage(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	s.LoadBuffers("getaccountusage.txt")
	if err := bb.GetAccountUsage(); err != nil {
		t.Errorf("get account usage: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}

func TestGetObjectName(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	s.LoadBuffers("getobjectname.txt")
	if _, err := bb.GetObjectName(0x273, 0x274); err != nil {
		s.PrintBuffers()
		t.Errorf("get object name: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}

func TestGetObject(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	// 000002a0 f----- bbackupd.conf
	// 0000029f f----- bbstored.conf
	// 0000029e f----- raidfile.conf
	s.LoadBuffers("getobject29E.txt")
	if _, err := bb.GetObject(0x29e); err != nil {
		t.Errorf("get object: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("getobject2A0.txt")
	if _, err := bb.GetObject(0x2a0); err != nil {
		t.Errorf("get object: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}

func TestGetFile(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	// 0000029d -d---- etc
	// 000002a0 f----- bbackupd.conf
	// 0000029f f----- bbstored.conf
	// 0000029e f----- raidfile.conf
	s.LoadBuffers("getfile.txt")
	if _, err := bb.GetFile(0x29d, 0x2a0); err != nil {
		t.Errorf("get file: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}

func TestGetBlockIndexById(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	s.LoadBuffers("getblockindexbyid.txt")
	if err := bb.GetBlockIndexByID(0x2a0); err != nil {
		t.Errorf("get blockindex by id: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}

func TestReadDir(t *testing.T) {
	s, bb := initServer(t)
	s.PrintBuffers()

	s.LoadBuffers("listdirectory.txt")
	if _, err := bb.ReadDir(0x276); err != nil {
		t.Errorf("list directory: %s", err)
		return
	}
	s.PrintBuffers()

	s.LoadBuffers("finish.txt")
	bb.Finish()
}
