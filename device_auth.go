package mdoc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type DeviceAuth struct {
	DeviceSignature *DeviceSignature `cbor:",omitempty"`
	// TODO DeviceMAC *DeviceMAC
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

func (da *DeviceAuth) Verify(
	deviceKey *DeviceKey,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) error {
	if da.DeviceSignature != nil {
		if err := verifySignature(deviceKey, da.DeviceSignature, deviceAuthenticationBytes); err != nil {
			return err
		}
	}

	return errors.New("TODO") // TODO
}

func verifySignature(
	deviceKey *DeviceKey,
	deviceSignature *DeviceSignature,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) error {
	signatureAlgorithm, err := deviceSignature.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	_, err = CipherSuite1.findCurveFromCOSEAlgorithm(signatureAlgorithm)
	if err != nil {
		return ErrUnsupportedAlgorithm
	}

	verifier, err := (*cose.Key)(deviceKey).Verifier()
	if err != nil {
		return err
	}

	return (*cose.Sign1Message)(deviceSignature).VerifyDetached(
		deviceAuthenticationBytes.TaggedValue,
		[]byte{},
		verifier,
	)
}
