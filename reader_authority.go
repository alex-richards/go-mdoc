package mdoc

import "crypto/x509"

type ReaderAuthority interface {
	Signer
	Certificate() x509.Certificate
}
