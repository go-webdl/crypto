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
