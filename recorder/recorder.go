package main

import (
	"bbq/client"
	"bbq/crypto"
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/kpango/glg"
)

var flagConfigFile = flag.String("config", "/etc/boxbackup/bbackupd.conf", "Main configuration file.")

type Recorder struct {
	net.Conn
	srv  io.ReadWriteCloser
	rbuf [][]byte
	wbuf [][]byte
}

func (r *Recorder) Read(p []byte) (int, error) {
	n, err := r.srv.Read(p)
	c := make([]byte, n)
	copy(c, p)
	r.rbuf = append(r.rbuf, c)
	return n, err
}
func (r *Recorder) Write(p []byte) (int, error) {
	c := make([]byte, len(p))
	copy(c, p)
	r.wbuf = append(r.wbuf, c)
	return r.srv.Write(p)
}

func (r *Recorder) ResetTrace() {
	r.rbuf = nil
	r.wbuf = nil
}

func (r *Recorder) dump(buf [][]byte, n string) error {
	f, err := os.Create(n)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, t := range buf {

		line := 30
		for i := 0; i < len(t); i += line {

			end := i + line
			if end > len(t) {
				end = len(t)
			}

			if _, err := w.WriteString(fmt.Sprintf("% X\n", t[i:end])); err != nil {
				return err
			}
		}
		if _, err := w.WriteString("\n"); err != nil {
			return err
		}
		w.Flush()
	}
	return nil
}

func (r *Recorder) DumpTrace(n string) error {
	if err := r.dump(r.rbuf, "r-"+n); err != nil {
		return err
	}
	if err := r.dump(r.wbuf, "w-"+n); err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()

	cfg, err := client.NewConfig(*flagConfigFile)
	if err != nil {
		glg.Error(err)
		return
	}

	cr, err := crypto.NewCrypto(cfg.Strings["KeysFile"])
	if err != nil {
		glg.Error(err)
		return
	}

	s, err := crypto.NewStoreConnection(
		"",
		cfg.Strings["TrustedCAsFile"],
		cfg.Strings["CertificateFile"],
		cfg.Strings["PrivateKeyFile"],
	)
	if err != nil {
		glg.Error(err)
	}

	r := &Recorder{}
	r.srv, err = s.Connect(cfg.Strings["StoreHostname"])
	if err != nil {
		glg.Error(err)
		return
	}
	defer r.srv.Close()

	bb := client.NewBoxBackup(r, cr)

	// Start recording

	if err := bb.CheckVersion(1); err != nil {
		glg.Error(err)
		return
	}
	bb.Login(1, false)
	r.DumpTrace("login.txt")
	r.ResetTrace()

	if err := bb.GetAccountUsage(); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getaccountusage.txt")
	r.ResetTrace()

	if _, err := bb.GetObjectName(0x273, 0x274); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getobjectname.txt")
	r.ResetTrace()

	// 000002a0 f----- bbackupd.conf
	// 0000029f f----- bbstored.conf
	// 0000029e f----- raidfile.conf
	if _, err := bb.GetObject(0x29e); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getobject29E.txt")
	r.ResetTrace()

	if _, err := bb.GetObject(0x2a0); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getobject2A0.txt")
	r.ResetTrace()

	// 0000029d -d---- etc
	// 000002a0 f----- bbackupd.conf
	// 0000029f f----- bbstored.conf
	// 0000029e f----- raidfile.conf
	if _, err := bb.GetFile(0x29d, 0x2a0); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getfile.txt")
	r.ResetTrace()

	if err := bb.GetBlockIndexByID(0x2a0); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("getblockindexbyid.txt")
	r.ResetTrace()

	if _, err := bb.ReadDir(0x276); err != nil {
		glg.Error(err)
		return
	}
	r.DumpTrace("listdirectory.txt")
	r.ResetTrace()

	bb.Finish()
	r.DumpTrace("finish.txt")
	return
}
