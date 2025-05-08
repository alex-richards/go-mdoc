package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	mdocX509 "github.com/alex-richards/go-mdoc/internal/x509"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrInvalidIACARootCertificate        = errors.New("mdoc: invalid IACA root certificate")
	ErrUnexpectedIntermediateCertificate = errors.New("mdoc: unexpected intermediate certificate")
	ErrInvalidDocumentSignerCertificate  = errors.New("mdoc: invalid document signer certificate")
	ErrDuplicateDigestID                 = errors.New("mdoc: duplicate digest ID")
)

const (
	MobileSecurityObjectVersion = "1.0"
)

const (
	IACAMaxAgeYears          = 20
	DocumentSignerMaxAgeDays = 457
)

var (
	DocumentSignerKeyUsage = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
)

type IssuerAuth cose.UntaggedSign1Message

func (ia *IssuerAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ia))
}
func (ia *IssuerAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ia))
}

func (ia *IssuerAuth) Verify(rootCertificates []*x509.Certificate, now time.Time) error {
	chain, err := coseX509Chain(ia.Headers.Unprotected)
	if err != nil {
		return err
	}

	issuerAuthCertificate, err := mdocX509.VerifyChain(
		rootCertificates,
		chain,
		now,
		ValidateIACACertificate,
		validateIntermediateDocumentCertificate,
		ValidateDocumentSignerCertificate,
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

func ValidateIACACertificate(iacaCertificate *x509.Certificate) error {
	if iacaCertificate.Version != 3 {
		return ErrInvalidIACARootCertificate
	}

	{
		country := iacaCertificate.Issuer.Country
		if len(country) != 1 {
			return ErrInvalidIACARootCertificate
		}

		lenCountry := len(country[0])
		if lenCountry != 2 && lenCountry != 3 {
			return ErrInvalidIACARootCertificate
		}

		// TODO check for valid country codes
		//if !strings.EqualFold(countries.ByName(country[0]).Alpha2(), country[0]) {
		//	return ErrInvalidIACARootCertificate
		//}
	}

	if len(iacaCertificate.Issuer.CommonName) == 0 {
		return ErrInvalidIACARootCertificate
	}

	{
		maxNotAfter := iacaCertificate.NotBefore.AddDate(IACAMaxAgeYears, 0, 0)
		if iacaCertificate.NotAfter.Compare(maxNotAfter) > 0 {
			return ErrInvalidIACARootCertificate
		}
	}

	if !bytes.Equal(iacaCertificate.RawIssuer, iacaCertificate.RawSubject) {
		return ErrInvalidIACARootCertificate
	}

	if iacaCertificate.PublicKeyAlgorithm != x509.ECDSA {
		return ErrInvalidIACARootCertificate
	}

	if iacaCertificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return ErrInvalidIACARootCertificate
	}

	if !iacaCertificate.IsCA {
		return ErrInvalidIACARootCertificate
	}

	if iacaCertificate.MaxPathLen != 0 {
		return ErrInvalidIACARootCertificate
	}

	switch iacaCertificate.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// allow
	default:
		return ErrInvalidIACARootCertificate
	}

	return nil
}

func validateIntermediateDocumentCertificate(_ *x509.Certificate, _ *x509.Certificate) error {
	return ErrUnexpectedIntermediateCertificate
}

func ValidateDocumentSignerCertificate(documentSignerCertificate *x509.Certificate, iacaCertificate *x509.Certificate) error {
	if documentSignerCertificate.Version != 3 {
		return ErrInvalidDocumentSignerCertificate
	}

	{
		maxNotAfter := documentSignerCertificate.NotBefore.AddDate(0, 0, DocumentSignerMaxAgeDays)
		if documentSignerCertificate.NotAfter.Compare(maxNotAfter) > 0 {
			return ErrInvalidDocumentSignerCertificate
		}
	}

	if !reflect.DeepEqual(documentSignerCertificate.Subject.Country, iacaCertificate.Subject.Country) {
		return ErrInvalidDocumentSignerCertificate
	}

	if len(iacaCertificate.Subject.Province) != 0 && !reflect.DeepEqual(documentSignerCertificate.Subject.Province, iacaCertificate.Subject.Province) {
		return ErrInvalidDocumentSignerCertificate
	}

	switch documentSignerCertificate.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		// allow
	default:
		return ErrInvalidDocumentSignerCertificate
	}

	switch documentSignerCertificate.PublicKeyAlgorithm {
	case x509.ECDSA:
		_, ok := documentSignerCertificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidDocumentSignerCertificate
		}

	case x509.Ed25519:
		_, ok := documentSignerCertificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidDocumentSignerCertificate
		}

	default:
		return ErrInvalidDocumentSignerCertificate
	}

	if !bytes.Equal(documentSignerCertificate.AuthorityKeyId, iacaCertificate.SubjectKeyId) {
		return ErrInvalidDocumentSignerCertificate
	}

	if documentSignerCertificate.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidDocumentSignerCertificate
	}

	if len(documentSignerCertificate.UnknownExtKeyUsage) != 1 {
		return ErrInvalidDocumentSignerCertificate
	}
	if !documentSignerCertificate.UnknownExtKeyUsage[0].Equal(DocumentSignerKeyUsage) {
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
	Version         string           `cbor:"version"`
	DigestAlgorithm DigestAlgorithm  `cbor:"digestAlgorithm"`
	ValueDigests    NameSpaceDigests `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo    `cbor:"deviceKeyInfo"`
	DocType         DocType          `cbor:"docType"`
	ValidityInfo    ValidityInfo     `cbor:"validityInfo"`
}

type NameSpaceDigests map[NameSpace]ValueDigests
type ValueDigests map[DigestID]Digest
type DigestID uint
type Digest []byte

type DeviceKeyInfo struct {
	DeviceKey         PublicKey          `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           *KeyInfo           `cbor:"keyInfo,omitEmpty"`
}

type KeyAuthorizations struct {
	NameSpaces   *AuthorizedNameSpaces   `cbor:"nameSpaces,omitempty"`
	DataElements *AuthorizedDataElements `cbor:"dataElements,omitempty"`
}

func (ka *KeyAuthorizations) Contains(nameSpace NameSpace, dataElementIdentifier DataElementIdentifier) bool {
	if ka == nil {
		return false
	}

	if ka.NameSpaces != nil {
		for _, authorizedNameSpace := range *ka.NameSpaces {
			if nameSpace == authorizedNameSpace {
				return true
			}
		}
	}

	if ka.DataElements != nil {
		authorizedDataElementIdentifiers, ok := (*ka.DataElements)[nameSpace]
		if ok {
			for _, authorizedDataElement := range authorizedDataElementIdentifiers {
				if dataElementIdentifier == authorizedDataElement {
					return true
				}
			}
		}
	}

	return false
}

type AuthorizedNameSpaces []NameSpace
type AuthorizedDataElements map[NameSpace]DataElementsArray
type DataElementsArray []DataElementIdentifier

type KeyInfo map[int]any

type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}
