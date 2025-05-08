package ecdsa

import (
	"crypto/x509"
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/issuer"
)

type issuerAuthority struct {
	signer Signer
	dsc    *x509.Certificate
}

func NewIssuerAuthority(signer Signer, dsc *x509.Certificate) (issuer.IssuerAuthority, error) {
	return &issuerAuthority{
		signer,
		dsc,
	}, nil
}

func (i issuerAuthority) Signer() mdoc.Signer {
	return i.signer
}

func (i issuerAuthority) DocumentSignerCertificate() *x509.Certificate {
	return i.dsc
}
