package issuer

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
	"reflect"
	"time"

	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
)

var (
	ErrIACAUnsupportedPublicKeyType                   = errors.New("mdoc: IACA unsupported public key type")
	ErrIACAUnsupportedValidityTooLong                 = errors.New("mdoc: IACA validity too long")
	ErrDocumentSignerUnsupportedPublicKeyType         = errors.New("mdoc: document signer unsupported public key type")
	ErrDocumentSignerValidityMustBeWithinIACAValidity = errors.New("mdoc: document signer must be within IACA validity")
	ErrDocumentSignerValidityTooLong                  = errors.New("mdoc: document signer validity too long")
	ErrDocumentSignerStateMustMatchIACA               = errors.New("mdoc: document signer state must match IACA")
)

type IssuerAuthority struct {
	Signer                    mdoc.Signer
	DocumentSignerCertificate *x509.Certificate
}

func NewIACACertificate(
	rand io.Reader,
	signer crypto.Signer,
	publicKey crypto.PublicKey,
	serialNumber big.Int,
	commonName string,
	country string, state *string,
	notBefore, notAfter time.Time,
) ([]byte, error) {
	_, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrIACAUnsupportedPublicKeyType
	}

	maxNotAfter := notBefore.AddDate(mdoc.IACAMaxAgeYears, 0, 0)
	if notAfter.Compare(maxNotAfter) > 0 {
		return nil, ErrIACAUnsupportedValidityTooLong
	}

	template := x509.Certificate{
		SerialNumber: &serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    []string{country},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
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
	iacaCertificate *x509.Certificate,
	publicKey crypto.PublicKey,
	serialNumber big.Int,
	commonName string,
	state *string,
	notBefore, notAfter time.Time,
) ([]byte, error) {
	switch publicKey.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey, ed448.PublicKey: // allow
	default:
		return nil, ErrDocumentSignerUnsupportedPublicKeyType
	}

	if notBefore.Compare(iacaCertificate.NotBefore) < 0 ||
		notAfter.Compare(iacaCertificate.NotAfter) > 0 {
		return nil, ErrDocumentSignerValidityMustBeWithinIACAValidity
	}

	maxNotAfter := notBefore.AddDate(0, 0, mdoc.DocumentSignerMaxAgeDays)
	if notAfter.Compare(maxNotAfter) > 0 {
		return nil, ErrDocumentSignerValidityTooLong
	}

	template := x509.Certificate{
		SerialNumber: &serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
			Country:    iacaCertificate.Subject.Country,
		},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.DocumentSignerKeyUsage},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}

	if state == nil {
		template.Subject.Province = iacaCertificate.Subject.Province
	} else {
		if iacaCertificate.Subject.Province == nil {
			template.Subject.Province = []string{*state}
		} else if !reflect.DeepEqual(iacaCertificate.Subject.Province, state) {
			return nil, ErrDocumentSignerStateMustMatchIACA
		} else {
			template.Subject.Province = []string{*state}
		}
	}

	return x509.CreateCertificate(
		rand,
		&template, iacaCertificate,
		publicKey, signer,
	)
}
