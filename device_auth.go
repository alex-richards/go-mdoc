package mdoc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type DeviceAuth struct {
	DeviceSignature DeviceSignature
	// TODO DeviceMAC DeviceMAC
}

type DeviceSignature cose.UntaggedSign1Message

func (ds *DeviceSignature) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ds))
}
func (ds *DeviceSignature) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ds))
}

// TODO type DeviceMAC cose.Mac0Message

type DeviceAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	DeviceAuthentication string
	SessionTranscript    SessionTranscript
	DocType              DocType
	DeviceNameSpaceBytes TaggedEncodedCBOR
}

func NewDeviceAuthentication(
	sessionTranscript SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes TaggedEncodedCBOR,
) *DeviceAuthentication {
	return &DeviceAuthentication{
		DeviceAuthentication: "DeviceAuthentication",
		SessionTranscript:    sessionTranscript,
		DocType:              docType,
		DeviceNameSpaceBytes: deviceNameSpaceBytes,
	}
}

func (da *DeviceAuth) Verify() error {
	return errors.New("TODO") // TODO
}
