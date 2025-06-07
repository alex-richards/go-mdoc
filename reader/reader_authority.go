package reader

import (
	"crypto/x509"

	"github.com/alex-richards/go-mdoc"
)

type ReaderAuthority struct {
	Signer          mdoc.Signer
	RootCertificate *x509.Certificate
}
