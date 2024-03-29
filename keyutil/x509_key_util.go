package keyutil

import (
	"crypto/x509"
	_pem "encoding/pem"
	"fmt"
)

func ParseX509CertificatePEM(pem []byte) (cert *x509.Certificate, err error) {
	block, _ := _pem.Decode(pem)
	if block == nil {
		err = fmt.Errorf("invalid PEM format: %w", ErrInvalidFormat)
		return
	} else if block.Type == "CERTIFICATE" {
		if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
			return
		}
	} else {
		err = fmt.Errorf("unsupported PEM type for X509 certificate: %s: %w", block.Type, ErrInvalidFormat)
		return
	}
	return
}

func ParseX509CertificateAuto(certBytes []byte) (cert *x509.Certificate, err error) {
	block, _ := _pem.Decode(certBytes)
	if block != nil && block.Type == "CERTIFICATE" {
		certBytes = block.Bytes
	}
	if cert, err = x509.ParseCertificate(certBytes); err != nil {
		err = fmt.Errorf("[crypto/keyutil.ParseX509CertificateAuto] cannot detect input certificate format: %w", ErrInvalidFormat)
		return
	}
	return
}

func EncodeX509CertificatePEM(cert *x509.Certificate) []byte {
	return _pem.EncodeToMemory(&_pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
