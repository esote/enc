// Package enc provides a simple interface for encrypting and decrypting data to
// a useful format.
//
// First, the data item is encoded to as a gob. Next, the encoding is compressed
// to the gzip format. This is encrypted with AES-256 in Galois/Counter mode.
// The input password is derived with argon2i and the hash is used as the key to
// AES. The output data is in the following format.
//
//	[enc version][argon2 salt][AES nonce][encrypted data]
//
// This format aims for minimal data size (from gzip), data integrity (from
// GCM), and data confidentiality (from AES).
package enc

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Errors related to invalid input data.
var (
	ErrNoNonce        = errors.New("enc: data does not contain a nonce")
	ErrNoSalt         = errors.New("enc: data does not contain a salt")
	ErrNoVersion      = errors.New("enc: data does not contain a version")
	ErrVersionInvalid = errors.New("enc: data contains an invalid version")
)

const saltSize = 64

// Version is the enc format version.
const Version uint64 = 1

// Decrypt data according to the specified format.
func Decrypt(data, password []byte, d interface{}) error {
	if len(data) < 8 {
		return ErrNoVersion
	}

	ver, data := data[:8], data[8:]
	switch binary.LittleEndian.Uint64(ver) {
	case 1:
		break
	default:
		return ErrVersionInvalid
	}

	if len(data) < saltSize {
		return ErrNoSalt
	}

	salt, data := data[:saltSize], data[saltSize:]
	c, err := aes.NewCipher(derive(password, salt))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ErrNoNonce
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(data[:0], nonce, data, nil)
	if err != nil {
		return err
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return err
	}

	if err = gob.NewDecoder(r).Decode(d); err != nil {
		_ = r.Close()
		return err
	}

	return r.Close()
}

// Encrypt data according to the specified format. A SHA-512 hash of the output
// data is given in hash.
func Encrypt(password []byte, e interface{}) (data, hash []byte, err error) {
	var encoded bytes.Buffer

	if err = gob.NewEncoder(&encoded).Encode(e); err != nil {
		return
	}

	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)

	if _, err = w.Write(encoded.Bytes()); err != nil {
		return
	}

	if err = w.Close(); err != nil {
		return
	}

	salt := make([]byte, saltSize)
	if _, err = rand.Read(salt); err != nil {
		return
	}

	c, err := aes.NewCipher(derive(password, salt))
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	var buf bytes.Buffer
	sha := sha512.New()
	mw := io.MultiWriter(&buf, sha)

	ver := make([]byte, 8)
	binary.LittleEndian.PutUint64(ver, Version)

	if _, err = mw.Write(ver); err != nil {
		return
	}

	if _, err = mw.Write(salt); err != nil {
		return
	}

	if _, err = mw.Write(nonce); err != nil {
		return
	}

	if _, err = mw.Write(gcm.Seal(nil, nonce, compressed.Bytes(), nil)); err != nil {
		return
	}

	return buf.Bytes(), sha.Sum(nil), nil
}

func derive(password, salt []byte) []byte {
	return argon2.Key(password, salt, 3, 32*1024, 4, 32)
}
