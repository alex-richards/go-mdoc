package mdoc

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
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
		checkIACACertificate,
		checkIACALinkCertificate,
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

	mobileSecurityObjectBytes, err := ia.MobileSecurityObjectBytes()
	if err != nil {
		return err
	}

	return (*cose.Sign1Message)(ia).VerifyDetached(
		mobileSecurityObjectBytes.TaggedValue,
		[]byte{},
		verifier,
	)
}

func checkIACACertificate(certificate *x509.Certificate) error {
	return errors.New("TODO") // TODO
}

func checkIACALinkCertificate(certificate *x509.Certificate, previous *x509.Certificate) error {
	return errors.New("TODO") // TODO
}

func checkDocumentSignerCertificate(certificate *x509.Certificate, previous *x509.Certificate) error {
	return errors.New("TODO") // TODO
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
