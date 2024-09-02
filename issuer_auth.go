package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
	"time"

	"github.com/biter777/countries"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrInvalidIACARootCertificate       = errors.New("invalid IACA root certificate")
	ErrInvalidIACALinkCertificate       = errors.New("invalid IACA link certificate")
	ErrInvalidDocumentSignerCertificate = errors.New("invalid document signer certificate")
)

type IssuerAuth cose.UntaggedSign1Message

func (ia *IssuerAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ia))
}
func (ia *IssuerAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ia))
}

func (ia *IssuerAuth) Verify(rootCertificates []*x509.Certificate, now time.Time) error {
	chain, err := x509Chain(ia.Headers.Unprotected)
	if err != nil {
		return err
	}

	issuerAuthCertificate, err := verifyChain(
		rootCertificates,
		chain,
		now,
		checkIACARootCertificate,
		nil,
		checkDocumentSignerCertificate,
	)
	if err != nil {
		return err
	}

	signatureAlgorithm, err := ia.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, issuerAuthCertificate.PublicKey)
	if err != nil {
		return err
	}

	return (*cose.Sign1Message)(ia).Verify(
		[]byte{},
		verifier,
	)
}

func checkIACARootCertificate(certificate *x509.Certificate) error {
	if certificate.Version != 3 {
		return ErrInvalidIACARootCertificate
	}

	{
		country := certificate.Issuer.Country
		if len(country) != 1 {
			return ErrInvalidIACARootCertificate
		}

		if !strings.EqualFold(countries.ByName(country[0]).Alpha2(), country[0]) {
			return ErrInvalidIACARootCertificate
		}
	}

	if len(certificate.Issuer.CommonName) == 0 {
		return ErrInvalidIACARootCertificate
	}

	{
		maxNotAfter := certificate.NotBefore.AddDate(20, 0, 0)
		if certificate.NotAfter.Compare(maxNotAfter) > 0 {
			return ErrInvalidIACARootCertificate
		}
	}

	if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) {
		return ErrInvalidIACARootCertificate
	}

	if certificate.PublicKeyAlgorithm != x509.ECDSA {
		return ErrInvalidIACARootCertificate
	}

	if certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return ErrInvalidIACARootCertificate
	}

	if !certificate.IsCA {
		return ErrInvalidIACARootCertificate
	}

	if certificate.MaxPathLen != 0 {
		return ErrInvalidIACARootCertificate
	}

	switch certificate.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// allow
	default:
		return ErrInvalidIACARootCertificate
	}

	return nil
}

func checkIACALinkCertificate(certificate *x509.Certificate, previous *x509.Certificate) error {
	return errors.New("TODO") // TODO
}

func checkDocumentSignerCertificate(certificate *x509.Certificate, previous *x509.Certificate) error {
	if certificate.Version != 3 {
		return ErrInvalidDocumentSignerCertificate
	}

	{
		maxNotAfter := certificate.NotBefore.AddDate(0, 0, 457)
		if certificate.NotAfter.Compare(maxNotAfter) > 0 {
			return ErrInvalidDocumentSignerCertificate
		}
	}

	//certificate.Subject.Country // TODO

	//certificate.Subject.Province // TODO

	switch certificate.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// allow
		//TODO edwards
	default:
		return ErrInvalidDocumentSignerCertificate
	}
	switch certificate.PublicKeyAlgorithm {
	case x509.ECDSA:
		_, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidDocumentSignerCertificate
		}

	case x509.Ed25519:
		_, ok := certificate.PublicKey.(*ed25519.PublicKey)
		if !ok {
			return ErrInvalidDocumentSignerCertificate
		}

	default:
		return ErrInvalidDocumentSignerCertificate
	}

	if !bytes.Equal(certificate.AuthorityKeyId, previous.SubjectKeyId) {
		return ErrInvalidDocumentSignerCertificate
	}

	if certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidDocumentSignerCertificate
	}

	if len(certificate.UnknownExtKeyUsage) != 1 {
		return ErrInvalidDocumentSignerCertificate
	}
	if !certificate.UnknownExtKeyUsage[0].Equal(asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}) {
		return ErrInvalidDocumentSignerCertificate
	}

	return nil
}

func (ia *IssuerAuth) MobileSecurityObjectBytes() (*TaggedEncodedCBOR, error) {
	mobileSecurityObjectBytes := new(TaggedEncodedCBOR)
	if err := cbor.Unmarshal(ia.Payload, mobileSecurityObjectBytes); err != nil {
		return nil, err
	}

	return mobileSecurityObjectBytes, nil
}

func (ia *IssuerAuth) MobileSecurityObject() (*MobileSecurityObject, error) {
	mobileSecurityObjectBytes, err := ia.MobileSecurityObjectBytes()
	if err != nil {
		return nil, err
	}

	mobileSecurityObject := new(MobileSecurityObject)
	if err = cbor.Unmarshal(mobileSecurityObjectBytes.UntaggedValue, mobileSecurityObject); err != nil {
		return nil, err
	}

	return mobileSecurityObject, nil
}

type MobileSecurityObject struct {
	Version         string          `cbor:"version"`
	DigestAlgorithm DigestAlgorithm `cbor:"digestAlgorithm"`
	ValueDigests    ValueDigests    `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo   `cbor:"deviceKeyInfo"`
	DocType         DocType         `cbor:"docType"`
	ValidityInfo    ValidityInfo    `cbor:"validityInfo"`
}

type DigestAlgorithm string

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
)

type ValueDigests map[NameSpace]DigestIDs
type DigestIDs map[DigestID]Digest
type DigestID uint
type Digest []byte

type DeviceKeyInfo struct {
	DeviceKey         *DeviceKey         `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           *KeyInfo           `cbor:"keyInfo,omitEmpty"`
}

type KeyAuthorizations struct {
	NameSpaces   *AuthorizedNameSpaces   `cbor:"nameSpaces,omitempty"`
	DataElements *AuthorizedDataElements `cbor:"dataElements,omitempty"`
}

type AuthorizedNameSpaces []NameSpace
type AuthorizedDataElements map[NameSpace]DataElementsArray
type DataElementsArray []DataElementIdentifier

type KeyInfo map[int]any

type ValidityInfo struct {
	Signed         time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	ExpectedUpdate *time.Time
}
