package mdoc

import "crypto/x509"

type ReaderAuthority interface {
	Signer
	RootCertificate() *x509.Certificate
}
