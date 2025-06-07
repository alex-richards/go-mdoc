package mdoc

import (
	"errors"

	cbor2 "github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrNoDeviceAuthPresent        = errors.New("mdoc: no device auth present")
	ErrMultipleDeviceAuthsPresent = errors.New("mdoc: multiple device auths present")

	ErrMACAuthNotSupported = errors.New("mdoc: MAC auth not supported")
)

type DeviceAuth struct {
	DeviceSignature *DeviceSignature `cbor:",omitempty"`
	DeviceMAC       *DeviceMAC       `cbor:",omitempty"`
}

func (da *DeviceAuth) Verify(
	deviceKey *PublicKey,
	deviceAuthenticationBytes *cbor2.TaggedEncodedCBOR,
) error {
	switch {
	case da.DeviceSignature != nil && da.DeviceMAC != nil:
		return ErrMultipleDeviceAuthsPresent

	case da.DeviceSignature != nil:
		return verifyDeviceSignature(deviceKey, da.DeviceSignature, deviceAuthenticationBytes)

	case da.DeviceMAC != nil:
		return ErrMACAuthNotSupported

	default:
		return ErrNoDeviceAuthPresent
	}
}

func verifyDeviceSignature(
	deviceKey *PublicKey,
	deviceSignature *DeviceSignature,
	deviceAuthenticationBytes *cbor2.TaggedEncodedCBOR,
) error {
	coseVerifier, err := (*cose.Key)(deviceKey).Verifier()
	if err != nil {
		return err
	}

	sign1 := (cose.Sign1Message)(*deviceSignature)
	sign1.Payload = deviceAuthenticationBytes.TaggedValue
	return sign1.Verify([]byte{}, coseVerifier)
}

type DeviceSignature cose.UntaggedSign1Message

func (ds *DeviceSignature) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ds))
}
func (ds *DeviceSignature) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ds))
}

type DeviceMAC any // TODO type DeviceMAC cose.MAC0Message

type DeviceAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	DeviceAuthentication string
	SessionTranscript    SessionTranscript
	DocType              DocType
	DeviceNameSpaceBytes cbor2.TaggedEncodedCBOR
}

func NewDeviceAuthenticationBytes(
	sessionTranscript *SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes *cbor2.TaggedEncodedCBOR,
) (*cbor2.TaggedEncodedCBOR, error) {
	return cbor2.MarshalToNewTaggedEncodedCBOR(NewDeviceAuthentication(sessionTranscript, docType, deviceNameSpaceBytes))
}

func NewDeviceAuthentication(
	sessionTranscript *SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes *cbor2.TaggedEncodedCBOR,
) *DeviceAuthentication {
	return &DeviceAuthentication{
		DeviceAuthentication: "DeviceAuthentication",
		SessionTranscript:    *sessionTranscript,
		DocType:              docType,
		DeviceNameSpaceBytes: *deviceNameSpaceBytes,
	}
}
