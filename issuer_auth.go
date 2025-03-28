package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrInvalidIACARootCertificate        = errors.New("invalid IACA root certificate")
	ErrUnexpectedIntermediateCertificate = errors.New("unexpected intermediate certificate")
	ErrInvalidDocumentSignerCertificate  = errors.New("invalid document signer certificate")
)

const (
	MobileSecurityObjectVersion = "1.0"
)

const (
	iacaMaxAgeYears          = 20
	documentSignerMaxAgeDays = 457
)

var (
	documentSignerKeyUsage = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}
)

type IssuerAuth cose.UntaggedSign1Message

func NewIssuerAuth(
	rand io.Reader,
	issuerAuthority IssuerAuthority,
	mobileSecurityObject *MobileSecurityObject,
) (*IssuerAuth, error) {
	mobileSecurityObjectBytes, err := MarshalToNewTaggedEncodedCBOR(mobileSecurityObject)
	if err != nil {
		return nil, err
	}

	issuerAuth := &IssuerAuth{
		Payload: mobileSecurityObjectBytes.TaggedValue,
	}

	err = coseSign(rand, issuerAuthority, issuerAuth)
	if err != nil {
		return nil, err
	}

	return issuerAuth, nil
}

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

	issuerAuthCertificate, err := x500VerifyChain(
		rootCertificates,
		chain,
		now,
		validateIACARootCertificate,
		validateIntermediateDocumentCertificate,
		validateDocumentSignerCertificate,
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

func validateIACARootCertificate(iacaCertificate *x509.Certificate) error {
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

		// TODO
		//if !strings.EqualFold(countries.ByName(country[0]).Alpha2(), country[0]) {
		//	return ErrInvalidIACARootCertificate
		//}
	}

	if len(iacaCertificate.Issuer.CommonName) == 0 {
		return ErrInvalidIACARootCertificate
	}

	{
		maxNotAfter := iacaCertificate.NotBefore.AddDate(iacaMaxAgeYears, 0, 0)
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

func validateDocumentSignerCertificate(documentSignerCertificate *x509.Certificate, iacaCertificate *x509.Certificate) error {
	if documentSignerCertificate.Version != 3 {
		return ErrInvalidDocumentSignerCertificate
	}

	{
		maxNotAfter := documentSignerCertificate.NotBefore.AddDate(0, 0, documentSignerMaxAgeDays)
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
		//TODO edwards
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
		_, ok := documentSignerCertificate.PublicKey.(*ed25519.PublicKey)
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
	if !documentSignerCertificate.UnknownExtKeyUsage[0].Equal(documentSignerKeyUsage) {
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

func NewMobileSecurityObject(
	docType DocType,
	digestAlgorithm DigestAlgorithm,
	nameSpaces IssuerNameSpaces,
	deviceKey *DeviceKey,
	validityInfo *ValidityInfo,
	keyAuthorizations *KeyAuthorizations,
	keyInfo *KeyInfo,
) (*MobileSecurityObject, error) {
	hash, err := digestAlgorithm.Hash()
	if err != nil {
		return nil, err
	}

	nameSpaceDigests := make(NameSpaceDigests, len(nameSpaces))
	for nameSpace, issuerSignedItemBytess := range nameSpaces {
		valueDigests := make(ValueDigests, len(issuerSignedItemBytess))
		nameSpaceDigests[nameSpace] = valueDigests
		for i, issuerSignedItemBytes := range issuerSignedItemBytess {
			digestId := (DigestID)(i)
			hash.Reset()
			hash.Write(issuerSignedItemBytes.TaggedValue)
			h := hash.Sum(nil)
			valueDigests[digestId] = h
		}
	}

	return &MobileSecurityObject{
		Version:         MobileSecurityObjectVersion,
		DigestAlgorithm: digestAlgorithm,
		ValueDigests:    nameSpaceDigests,
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey:         *deviceKey,
			KeyAuthorizations: keyAuthorizations,
			KeyInfo:           keyInfo,
		},
		DocType:      docType,
		ValidityInfo: *validityInfo,
	}, nil
}

type NameSpaceDigests map[NameSpace]ValueDigests
type ValueDigests map[DigestID]Digest
type DigestID uint
type Digest []byte

type DeviceKeyInfo struct {
	DeviceKey         DeviceKey          `cbor:"deviceKey"`
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
	Signed         time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	ExpectedUpdate *time.Time
}
