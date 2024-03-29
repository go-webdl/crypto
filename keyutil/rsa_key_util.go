package keyutil

import (
	"crypto/rsa"
	"crypto/x509"
	_pem "encoding/pem"
	"fmt"
)

func ParseRSAPrivateKeyPEM(pem []byte) (key *rsa.PrivateKey, err error) {
	block, _ := _pem.Decode(pem)
	if block == nil {
		err = fmt.Errorf("invalid PEM format: %w", ErrInvalidFormat)
		return
	} else if block.Type == "RSA PRIVATE KEY" {
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return
		}
	} else if block.Type == "PRIVATE KEY" {
		var _key interface{}
		if _key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return
		}
		var ok bool
		if key, ok = _key.(*rsa.PrivateKey); !ok {
			err = fmt.Errorf("key encoded in PKCS8 is not a RSA private key: %w", ErrInvalidFormat)
			return
		}
	} else {
		err = fmt.Errorf("unsupported PEM type for RSA private key: %s: %w", block.Type, ErrInvalidFormat)
		return
	}
	return
}

func EncodeRSAPrivateKeyPKCS1PEM(key *rsa.PrivateKey) []byte {
	return _pem.EncodeToMemory(&_pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func EncodePrivateKeyPKCS8PEM(key any) (pem []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		err = fmt.Errorf("[keyutil.EncodePrivateKeyPKCS8PEM] x509.MarshalPKCS8PrivateKey: %w", err)
		return
	}
	pem = _pem.EncodeToMemory(&_pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	return
}
