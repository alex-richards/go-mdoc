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
)

type DeviceAuth struct {
	DeviceSignature *DeviceSignature `cbor:",omitempty"`
	DeviceMAC       *DeviceMAC       `cbor:",omitempty"`
}

func NewDeviceAuth(
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	deviceAuthentication DeviceAuthentication,
) (*DeviceAuth, error) {
	signer, err := newCoseSigner(privateSDeviceKey)
	if err != nil {
		return nil, err
	}

	deviceAuthenticationBytes, err := MarshalToNewTaggedEncodedCBOR(deviceAuthentication)
	if err != nil {
		return nil, err
	}

	deviceSignature := &DeviceSignature{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{
				cose.HeaderLabelAlgorithm: signer.Algorithm(),
			},
		},
		Payload: deviceAuthenticationBytes.TaggedValue,
	}

	err = (*cose.Sign1Message)(deviceSignature).Sign(rand, []byte{}, signer)
	if err != nil {
		return nil, err
	}
	deviceSignature.Payload = nil

	return &DeviceAuth{DeviceSignature: deviceSignature}, nil
}

func (da *DeviceAuth) Verify(
	deviceKey DeviceKey,
	deviceAuthentication DeviceAuthentication,
) error {
	switch {
	case da.DeviceSignature != nil && da.DeviceMAC != nil:
		return ErrMultipleDeviceAuthsPresent

	case da.DeviceSignature != nil:
		return verifyDeviceSignature(deviceKey, *da.DeviceSignature, deviceAuthentication)

	case da.DeviceMAC != nil:
		return errors.New("TODO coseMac0") // TODO

	default:
		return ErrNoDeviceAuthPresent
	}
}

func verifyDeviceSignature(
	deviceKey DeviceKey,
	deviceSignature DeviceSignature,
	deviceAuthentication DeviceAuthentication,
) error {
	deviceAuthenticationBytes, err := MarshalToNewTaggedEncodedCBOR(deviceAuthentication)
	if err != nil {
		return err
	}

	verifier, err := (*cose.Key)(&deviceKey).Verifier()
	if err != nil {
		return err
	}

	sign1 := (cose.Sign1Message)(deviceSignature)
	sign1.Signature = deviceAuthenticationBytes.TaggedValue
	return sign1.Verify(
		[]byte{},
		verifier,
	)
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
