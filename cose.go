package mdoc

import (
	"crypto/x509"
	"errors"

	"github.com/veraison/go-cose"
)

func X509Chain(from cose.UnprotectedHeader) ([]*x509.Certificate, error) {
	x509ChainHeader := from[cose.HeaderLabelX5Chain]

	switch x509ChainEncoded := x509ChainHeader.(type) {
	case []byte:
		cert, err := x509.ParseCertificate(x509ChainEncoded)
		if err != nil {
			return nil, err
		}

		return []*x509.Certificate{cert}, nil
	case [][]byte:
		certs := make([]*x509.Certificate, len(x509ChainEncoded))
		for i, certEncoded := range x509ChainEncoded {
			cert, err := x509.ParseCertificate(certEncoded)
			if err != nil {
				return nil, err
			}
			certs[i] = cert
		}
		return certs, nil
	default:
		return nil, errors.New("TODO - header type wrong")
	}
}
