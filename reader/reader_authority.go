package reader

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
)

var (
	ErrReaderAuthenticationUnsupportedPublicKeyType = errors.New("mdoc: readerauth: unsupported public key type")
)

type ReaderAuthority struct {
	Signer          mdoc.Signer
	RootCertificate *x509.Certificate
}

func NewReaderAuthenticationCertificate(
	rand io.Reader,
	signer crypto.Signer,
	readerAuthIssuerCertificate x509.Certificate,
	publicKey crypto.PublicKey,
	serialNumber big.Int,
	subject pkix.Name,
	notBefore, notAfter time.Time,
) ([]byte, error) {
	switch publicKey.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey, ed448.PublicKey: // allow
	default:
		return nil, errors.New("TODO error")
	}

	if notBefore.Compare(readerAuthIssuerCertificate.NotBefore) < 0 ||
		notAfter.Compare(readerAuthIssuerCertificate.NotAfter) > 0 {
		return nil, errors.New("TODO error")
	}

	maxNotAfter := notBefore.AddDate(0, 0, mdoc.ReaderAuthMaxAgeDays)
	if notAfter.Compare(maxNotAfter) > 0 {
		return nil, errors.New("TODO error")
	}

	template := x509.Certificate{
		SerialNumber:          &serialNumber,
		Subject:               subject,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{mdoc.ReaderAuthenticationKeyUsage},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // TODO remove
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}

	return x509.CreateCertificate(
		rand,
		&template, &readerAuthIssuerCertificate,
		publicKey, signer,
	)
}
