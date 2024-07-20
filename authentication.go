package mdoc

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type EDeviceKeyBytes TaggedEncodedCBOR
type EReaderKeyBytes TaggedEncodedCBOR

type ReaderAuth cose.UntaggedSign1Message

func (ra *ReaderAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ra))
}
func (ra *ReaderAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ra))
}

type ReadReaderAuthenticationBytes TaggedEncodedCBOR
type ReaderAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	ReaderAuthentication string
	SessionTranscript    SessionTranscript
	ItemsRequestBytes    ItemsRequestBytes
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

type DeviceSignature cose.UntaggedSign1Message

func (ds *DeviceSignature) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ds))
}
func (ds *DeviceSignature) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ds))
}

// type DeviceMAC cose.Mac0Message
