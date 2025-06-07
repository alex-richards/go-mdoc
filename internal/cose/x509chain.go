package cose

import (
	"crypto/x509"
	"errors"

	"github.com/veraison/go-cose"
)

var (
	ErrUnrecognisedHeaderType = errors.New("mdoc: cose: unrecognized cose header type")
)

func X509Chain(from cose.UnprotectedHeader) ([]*x509.Certificate, error) {
	x5c := from[cose.HeaderLabelX5Chain]

	switch encoded := x5c.(type) {
	case []byte:
		cert, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil

	case [][]byte:
		certs := make([]*x509.Certificate, len(encoded))
		for i, certEncoded := range encoded {
			cert, err := x509.ParseCertificate(certEncoded)
			if err != nil {
				return nil, err
			}
			certs[i] = cert
		}
		return certs, nil

	default:
		return nil, ErrUnrecognisedHeaderType
	}
}
