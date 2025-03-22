package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"time"
)

type IssuerAuthority interface {
	Signer
	Certificate() x509.Certificate
}

func NewIACACertificate(
	rand io.Reader,
	signer crypto.Signer,
	publicKey crypto.PublicKey,
	commonName string,
	country string, state *string,
	notBefore, notAfter time.Time,
) ([]byte, error) {
	_, ok := publicKey.(ecdsa.PublicKey)
	if !ok {
		// TODO
	}

	maxNotAfter := notBefore.AddDate(iacaMaxAgeYears, 0, 0)
	if notAfter.Compare(maxNotAfter) > 0 {
		// TODO
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if state != nil {
		template.Subject.Province = []string{*state}
	}

	return x509.CreateCertificate(
		rand,
		&template, &template,
		publicKey, signer,
	)
}

func NewDocumentSignerCertificate(
	rand io.Reader,
	signer crypto.Signer,
	iacaCertificate x509.Certificate,
	publicKey crypto.PublicKey,
	commonName string,
	state *string,
	notBefore, notAfter time.Time,
) ([]byte, error) {
	switch publicKey.(type) {
	case ecdsa.PublicKey, ed25519.PrivateKey: // allow
	default: // TODO error
	}

	maxNotAfter := notBefore.AddDate(0, 0, documentSignerMaxAgeDays)
	if notAfter.Compare(maxNotAfter) > 0 {
		// TODO error
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    iacaCertificate.Subject.Country,
			Province:   iacaCertificate.Subject.Province,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{documentSignerKeyUsage},
	}
	if state != nil {
		if iacaCertificate.Subject.Province != nil {
			// TODO error
		}
		template.Subject.Province = []string{*state}
	}

	return x509.CreateCertificate(
		rand,
		&template, &iacaCertificate,
		publicKey, signer,
	)
}
