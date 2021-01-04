package crypto

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/blowfish"
)

/*
// All keys are the maximum size that Blowfish supports. Since only the setup
// time is affected by key length (encryption same speed whatever) there is no
// disadvantage to using long keys as they are never transmitted and are static
// over long periods of time.

// All sizes in bytes. Some gaps deliberately left in the used material.

// How long the key material file is expected to be
#define BACKUPCRYPTOKEYS_FILE_SIZE						1024

// key for encrypting filenames (448 bits)
#define BACKUPCRYPTOKEYS_FILENAME_KEY_START				0
#define BACKUPCRYPTOKEYS_FILENAME_KEY_LENGTH			56
#define BACKUPCRYPTOKEYS_FILENAME_IV_START				(0 + BACKUPCRYPTOKEYS_FILENAME_KEY_LENGTH)
#define BACKUPCRYPTOKEYS_FILENAME_IV_LENGTH				8

// key for encrypting attributes (448 bits)
#define BACKUPCRYPTOKEYS_ATTRIBUTES_KEY_START			(BACKUPCRYPTOKEYS_FILENAME_KEY_START+64)
#define BACKUPCRYPTOKEYS_ATTRIBUTES_KEY_LENGTH			56

// Blowfish key for encrypting file data (448 bits (max blowfish key length))
#define BACKUPCRYPTOKEYS_FILE_KEY_START					(BACKUPCRYPTOKEYS_ATTRIBUTES_KEY_START+64)
#define BACKUPCRYPTOKEYS_FILE_KEY_LENGTH				56

// key for encrypting file block index entries
#define BACKUPCRYPTOKEYS_FILE_BLOCK_ENTRY_KEY_START		(BACKUPCRYPTOKEYS_FILE_KEY_START+64)
#define BACKUPCRYPTOKEYS_FILE_BLOCK_ENTRY_KEY_LENGTH	56

// Secret for hashing attributes
#define BACKUPCRYPTOKEYS_ATTRIBUTE_HASH_SECRET_START	(BACKUPCRYPTOKEYS_FILE_BLOCK_ENTRY_KEY_START+64)
#define BACKUPCRYPTOKEYS_ATTRIBUTE_HASH_SECRET_LENGTH	128

// AES key for encrypting file data (256 bits (max AES key length))
#define BACKUPCRYPTOKEYS_FILE_AES_KEY_START				(BACKUPCRYPTOKEYS_ATTRIBUTE_HASH_SECRET_START+128)
#define BACKUPCRYPTOKEYS_FILE_AES_KEY_LENGTH			32
*/

type Crypto struct {
	keyFilename      []byte
	keyFilenameIV    []byte
	keyAttributes    []byte
	keyFileDataBF    []byte
	keyBlockIndex    []byte
	secretAttributes []byte
	keyFileDataAES   []byte
}

func NewCrypto(keyFile string) (*Crypto, error) {
	f, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(f)

	c := &Crypto{
		keyFilename:   make([]byte, 56), // 0
		keyFilenameIV: make([]byte, 8),
		keyAttributes: make([]byte, 56), // 64
		// skip 8
		keyFileDataBF: make([]byte, 56), // 128
		// skip 8
		keyBlockIndex: make([]byte, 56), // 192
		// skip 8
		secretAttributes: make([]byte, 128), // 256
		keyFileDataAES:   make([]byte, 32),  // 384
	}
	r.Read(c.keyFilename[:])
	r.Read(c.keyFilenameIV[:])
	r.Read(c.keyAttributes[:])
	r.Seek(8, io.SeekCurrent)

	r.Read(c.keyFileDataBF[:])
	r.Seek(8, io.SeekCurrent)

	r.Read(c.keyBlockIndex[:])
	r.Seek(8, io.SeekCurrent)

	r.Read(c.secretAttributes[:])
	r.Read(c.keyFileDataAES[:])

	return c, nil
}

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) []byte {
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) []byte {
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return b
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return b
		}
	}
	return b[:len(b)-n]
}

func (c *Crypto) EncryptAttributes(at []byte, iv []byte) ([]byte, error) {
	ct := pkcs7Pad(at, blowfish.BlockSize)
	if err := cryptBlowfish(true, ct, c.keyAttributes, iv); err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}

func (c *Crypto) DecryptAttributes(at []byte) ([]byte, error) {
	iv := at[:blowfish.BlockSize]
	ct := at[blowfish.BlockSize:]
	if err := cryptBlowfish(false, ct, c.keyAttributes, iv); err != nil {
		return nil, err
	}
	return pkcs7Unpad(ct, blowfish.BlockSize), nil
}

func (c *Crypto) DecryptFilename(fn []byte) ([]byte, error) {
	if err := cryptBlowfish(false, fn, c.keyFilename, c.keyFilenameIV); err != nil {
		return nil, err
	}
	return pkcs7Unpad(fn, blowfish.BlockSize), nil
}

func (c *Crypto) EncryptFilename(fn []byte) ([]byte, error) {
	p := pkcs7Pad(fn, blowfish.BlockSize)
	return p, cryptBlowfish(true, p, c.keyFilename, c.keyFilenameIV)
}

func (c *Crypto) EncryptBlockIndexEntry(be []byte, iv []byte) error {
	return cryptBlowfish(true, be, c.keyBlockIndex, iv)
}

func (c *Crypto) DecryptBlockIndexEntry(be []byte, iv []byte) error {
	return cryptBlowfish(false, be, c.keyBlockIndex, iv)
}

func cryptBlowfish(enc bool, ct, key, iv []byte) error {
	ci, err := blowfish.NewCipher(key)
	if err != nil {
		return err
	}
	if len(ct)%blowfish.BlockSize != 0 {
		return fmt.Errorf("blowfish text is not a multiple of %v", blowfish.BlockSize)
	}
	var cbc cipher.BlockMode
	if enc {
		cbc = cipher.NewCBCEncrypter(ci, iv)
	} else {
		cbc = cipher.NewCBCDecrypter(ci, iv)
	}
	cbc.CryptBlocks(ct, ct)
	return nil
}

func (c *Crypto) EncryptFileData(fd, iv []byte) ([]byte, error) {
	ct := pkcs7Pad(fd, aes.BlockSize)
	if _, err := cryptAES(true, ct, c.keyFileDataAES, iv); err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}

func (c *Crypto) DecryptFileData(fd []byte) ([]byte, error) {
	iv := fd[:aes.BlockSize]
	ct := fd[aes.BlockSize:]
	if _, err := cryptAES(false, ct, c.keyFileDataAES, iv); err != nil {
		return nil, err
	}
	return pkcs7Unpad(ct, aes.BlockSize), nil
}

func cryptAES(enc bool, ct, key, iv []byte) ([]byte, error) {
	ci, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES text is not a multiple of %v", aes.BlockSize)
	}
	var cbc cipher.BlockMode
	if enc {
		cbc = cipher.NewCBCEncrypter(ci, iv)
	} else {
		cbc = cipher.NewCBCDecrypter(ci, iv)
	}
	cbc.CryptBlocks(ct, ct)
	return ct, nil
}

func (c *Crypto) Decompress(in, out []byte) error {
	nr := bytes.NewReader(in)
	unp, err := zlib.NewReader(nr)
	if err != nil {
		return fmt.Errorf("decompression error: %v", err)
	}
	unp.Read(out)
	return nil
}

/*
func (c *Crypto) encryptBlowfish(ct, key, iv []byte) error {
	ci, err := blowfish.NewCipher(key)
	if err != nil {
		return err
	}
	if len(ct)%blowfish.BlockSize != 0 {
		return fmt.Errorf("blowfish text is not a multiple of %v", blowfish.BlockSize)
	}

	enc := cipher.NewCBCEncrypter(ci, iv)
	enc.CryptBlocks(ct, ct)
	return nil
}
*/
