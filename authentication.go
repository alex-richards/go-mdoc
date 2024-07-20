package mdoc

import (
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type ReaderAuth cose.UntaggedSign1Message

func (ra *ReaderAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ra))
}
func (ra *ReaderAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ra))
}

type ReaderAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	ReaderAuthentication string
	SessionTranscript    SessionTranscript
	ItemsRequestBytes    TaggedEncodedCBOR
}

func NewReaderAuthentication(
	sessionTranscript SessionTranscript,
	itemsRequestBytes TaggedEncodedCBOR,
) *ReaderAuthentication {
	return &ReaderAuthentication{
		ReaderAuthentication: "ReaderAuthentication",
		SessionTranscript:    sessionTranscript,
		ItemsRequestBytes:    itemsRequestBytes,
	}
}

type IssuerAuth cose.UntaggedSign1Message

func (ia *IssuerAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ia))
}
func (ia *IssuerAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ia))
}

type DeviceAuth struct {
	DeviceSignature DeviceSignature
	// DeviceMAC DeviceMAC
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

	mobileSecurityObjectBytesUntagged, err := mobileSecurityObjectBytes.UntaggedValue()
	if err != nil {
		return nil, err
	}

	mobileSecurityObject := new(MobileSecurityObject)
	if err = cbor.Unmarshal(mobileSecurityObjectBytesUntagged, mobileSecurityObject); err != nil {
		return nil, err
	}

	return mobileSecurityObject, nil
}

type DeviceSignature cose.UntaggedSign1Message

func (ds *DeviceSignature) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ds))
}
func (ds *DeviceSignature) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ds))
}

// type DeviceMAC cose.Mac0Message

type MobileSecurityObject struct {
	Version         string          `cbor:"version"`
	DigestAlgorithm DigestAlgorithm `cbor:"digestAlgorithm"`
	ValueDigests    ValueDigests    `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo   `cbor:"deviceKeyInfo"`
	DocType         DocType         `cbor:"docType"`
	ValidityInfo    ValidityInfo    `cbor:"validityInfo"`
}

type DigestAlgorithm string

type ValueDigests map[NameSpace]DigestIDs
type DigestIDs map[DigestID]Digest
type DigestID uint
type Digest []byte

type DeviceKeyInfo struct {
	DeviceKey         DeviceKey          `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           *KeyInfo           `cbor:"keyInfo,omitEmpty"`
}

type DeviceKey cose.Key

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
