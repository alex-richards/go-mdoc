package mdoc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"io"
)

var (
	ErrNoDeviceAuthPresent        = errors.New("no device auth present")
	ErrMultipleDeviceAuthsPresent = errors.New("multiple device auths present")

	ErrMACAuthNotSupported = errors.New("MAC auth not supported")
)

type DeviceAuth struct {
	DeviceSignature *DeviceSignature `cbor:",omitempty"`
	DeviceMAC       *DeviceMAC       `cbor:",omitempty"`
}

func NewDeviceAuth(
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) (*DeviceAuth, error) {
	switch privateSDeviceKey.Mode() {
	case SDeviceKeyModeSign:
		return newSignedDeviceAuth(rand, privateSDeviceKey, deviceAuthenticationBytes)
	case SDeviceKeyModeMAC:
		return newTaggedDeviceAuth()
	default:
		panic("invalid privateSDeviceKey mode")
	}
}

func newSignedDeviceAuth(
	rand io.Reader,
	signer Signer,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) (*DeviceAuth, error) {
	deviceAuth := &DeviceAuth{DeviceSignature: &DeviceSignature{}}

	coseSigner, err := newCoseSigner(signer)
	if err != nil {
		return nil, err
	}

	deviceAuth.DeviceSignature.Payload = deviceAuthenticationBytes.TaggedValue
	err = (*cose.Sign1Message)(deviceAuth.DeviceSignature).Sign(rand, []byte{}, coseSigner)
	deviceAuth.DeviceSignature.Payload = nil
	return deviceAuth, nil
}

func newTaggedDeviceAuth() (*DeviceAuth, error) {
	return nil, ErrMACAuthNotSupported
}

func (da *DeviceAuth) Verify(
	deviceKey *DeviceKey,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
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
	deviceKey *DeviceKey,
	deviceSignature *DeviceSignature,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) error {
	coseVerifier, err := (*cose.Key)(deviceKey).Verifier()
	if err != nil {
		return err
	}

	deviceSignature.Payload = deviceAuthenticationBytes.TaggedValue
	err = (*cose.Sign1Message)(deviceSignature).Verify([]byte{}, coseVerifier)
	deviceSignature.Payload = nil
	return err
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
	DeviceNameSpaceBytes TaggedEncodedCBOR
}

func NewDeviceAuthenticationBytes(
	sessionTranscript *SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes *TaggedEncodedCBOR,
) (*TaggedEncodedCBOR, error) {
	return MarshalToNewTaggedEncodedCBOR(NewDeviceAuthentication(sessionTranscript, docType, deviceNameSpaceBytes))
}

func NewDeviceAuthentication(
	sessionTranscript *SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes *TaggedEncodedCBOR,
) *DeviceAuthentication {
	return &DeviceAuthentication{
		DeviceAuthentication: "DeviceAuthentication",
		SessionTranscript:    *sessionTranscript,
		DocType:              docType,
		DeviceNameSpaceBytes: *deviceNameSpaceBytes,
	}
}
