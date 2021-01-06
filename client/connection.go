package client

import (
	"bbq/client/proto"
	"bbq/crypto"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"

	"github.com/kpango/glg"
)

type BoxBackup struct {
	conn  net.Conn
	crypt *crypto.Crypto
	ready bool
	/*
		version    uint32
		user       uint32
	*/
}

type Operation struct {
	Op     interface{}
	Tail   []byte        // For variable trailers
	Stream *bytes.Buffer // Follow up with this stream
}

func NewBoxBackup(srv net.Conn, crypt *crypto.Crypto) *BoxBackup {
	return &BoxBackup{
		conn:  srv,
		crypt: crypt,
		ready: false,
	}
}

// Initial handshake on the connection.
// Client sends 32 bytes with magic string and server replies with the same.
func handshake(rw io.ReadWriter) error {
	var hs [proto.HandshakeLen]byte
	copy(hs[:], proto.Handshake)
	if err := binary.Write(rw, binary.LittleEndian, &hs); err != nil {
		return fmt.Errorf("encode error: %s", err)
	}
	var rep [proto.HandshakeLen]byte
	if n, err := rw.Read(rep[:]); err != nil && n != len(rep) {
		return fmt.Errorf("handshake error: %s", err)
	}
	if hs != rep {
		return fmt.Errorf("handshake failed: % X", rep)
	}
	return nil
}

// Sends a command to server and returns an expected response
func sendCommand(c io.Writer, op *Operation) (uint32, error) {
	t := reflect.TypeOf(op.Op).String()
	cmd, ok := proto.Commands[t]
	if !ok {
		return 0, fmt.Errorf("unknown command %v", t)
	}

	hdr := proto.Header{
		Command: cmd[0],
	}
	hdr.Size = uint32(binary.Size(hdr) + binary.Size(op.Op) + len(op.Tail))

	if err := binary.Write(c, binary.BigEndian, hdr); err != nil {
		return 0, err
	}
	if err := binary.Write(c, binary.BigEndian, op.Op); err != nil {
		return 0, err
	}
	glg.Infof("sent hdr: %+v", hdr)

	if op.Tail != nil {
		c.Write(op.Tail)
	}
	return cmd[1], nil
}

// Recieves server response and checks for expected type.
func getResponse(r io.Reader, exp uint32) (interface{}, error) {
	var hdr proto.Header
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}
	glg.Infof("recv hdr: %+v", hdr)
	if hdr.Command > 0 && hdr.Command != exp {
		return nil, fmt.Errorf("unexpected response from server: %+v", hdr)
	}

	resp, ok := proto.GetCommand(hdr.Command)
	if !ok {
		return nil, fmt.Errorf("invalid command: %v", hdr.Command)
	}

	// Get the full response into buffer
	buf := make([]byte, hdr.Size-uint32(binary.Size(hdr)))
	if n, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	} else if n != binary.Size(resp) {
		glg.Warnf("Warning: extra bytes sent by server: %v vs. %v", n, binary.Size(resp))
	}

	// Parse the response from buffer
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (b *BoxBackup) HandleError(ret *proto.Error) error {
	var errorSubtype = []string{
		"Success",
		"WrongVersion",              // 1
		"NotInRightProtocolPhase",   // 2
		"BadLogin",                  // 3
		"CannotLockStoreForWriting", // 4
		"SessionReadOnly",           // 5
		"FileDoesNotVerify",         // 6
		"DoesNotExist",              // 7
		"DirectoryAlreadyExists",    // 8
		"CannotDeleteRoot",          // 9
		"TargetNameExists",          // 10
		"StorageLimitExceeded",      // 11
		"DiffFromFileDoesNotExist",  // 12
		"DoesNotExistInDirectory",   // 13
		"PatchConsistencyError",     // 14
		"MultiplyReferencedObject",  // 15
		"DisabledAccount",           // 16
	}
	glg.Error(ret)
	if ret.Type == 1000 && int(ret.SubType) > 0 && int(ret.SubType) < len(errorSubtype) {
		return fmt.Errorf("error: %s", errorSubtype[ret.SubType])
	}

	return fmt.Errorf("unknown error: (%v, %v)", ret.Type, ret.SubType)
}

// Takes one of the structures defined in proto.go and writes them to the wire,
// gets reponse from the server and packs it into an appropriate struct.
func (b *BoxBackup) Execute(op *Operation) (interface{}, error) {

	if !b.ready {
		if err := handshake(b.conn); err != nil {
			return nil, err
		}
		b.ready = true
	}

	exp, err := sendCommand(b.conn, op)
	if err != nil {
		return nil, err
	}

	if op.Stream != nil {
		// Follow up this command with a stream
		hdr := proto.Header{
			Command: proto.STREAM_TYPE,
		}
		//hdr.Size = uint32(binary.Size(hdr) + len(op.Stream))
		hdr.Size = uint32(op.Stream.Len())
		binary.Write(b.conn, binary.BigEndian, &hdr)
		op.Stream.WriteTo(b.conn)
	}

	// Read back the response header
	r, err := getResponse(b.conn, exp)
	if err != nil {
		return nil, err
	}

	switch p := r.(type) {
	case *proto.Success:
		glg.Infof("Operation Successful: %+v", r)

	case *proto.Error:
		return nil, fmt.Errorf("Operation failed: %s", b.HandleError(p))
	}
	return r, nil
}

func (b *BoxBackup) GetStream() (*Stream, error) {
	glg.Debug("reading stream")
	var hdr proto.Header
	if err := binary.Read(b.conn, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	if hdr.Command != proto.STREAM_TYPE {
		return nil, fmt.Errorf("No stream available")
	}

	glg.Debugf("stream: %v bytes", hdr.Size)
	/*
		st := &proto.Stream{
			Size:   hdr.Size,
			Buffer: make([]byte, hdr.Size),
		}
		if n, err := io.ReadFull(b.connection, st.Buffer); err != nil || n != int(hdr.Size) {
			return nil, fmt.Errorf("Error reading full stream: %s", err)
		}
		st.Reader = bytes.NewReader(st.Buffer)
	*/
	return &Stream{
		size:   hdr.Size,
		reader: bufio.NewReader(b.conn),
	}, nil
}
