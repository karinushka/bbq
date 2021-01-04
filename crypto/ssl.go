package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

type StoreConnection struct {
	config *tls.Config
}

//
// Takes following crypto parameters
//  host - server hostname used for TLS verification.
//  ca - server trusted certificate authority.
//  cert - certificate from own pair.
//  key - private key from own pair.
//
func NewStoreConnection(host, ca, cert, key string) (*StoreConnection, error) {

	serverPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, fmt.Errorf("unable to read CA: %s", err)
	}

	// First, create the server certificate.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(serverPEM)) {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	mycert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("loading certificates: %s", err)
	}

	skip := len(host) == 0
	s := &StoreConnection{
		config: &tls.Config{
			ServerName:         host,
			RootCAs:            roots,
			Certificates:       []tls.Certificate{mycert},
			InsecureSkipVerify: skip,
		},
	}
	return s, nil
}

func (s *StoreConnection) Connect(host string) (*tls.Conn, error) {
	if len(host) == 0 {
		host = s.config.ServerName

	}
	c, err := tls.Dial("tcp", fmt.Sprintf("%s:2201", host), s.config)
	if err != nil {
		return nil, err
	}
	return c, nil
}
