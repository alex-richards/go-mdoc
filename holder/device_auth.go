package holder

import (
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/veraison/go-cose"
)

// NewDeviceAuth creates a new DeviceAuth, signed using the provided SDeviceKey.
// TODO MAC auth
func NewDeviceAuth(
	rand io.Reader,
	privateSDeviceKey *mdoc.PrivateKey,
	deviceAuthenticationBytes *cbor.TaggedEncodedCBOR,
) (*mdoc.DeviceAuth, error) {
	switch {
	case privateSDeviceKey.Signer != nil && privateSDeviceKey.Agreer == nil:
		return newSignedDeviceAuth(rand, privateSDeviceKey, deviceAuthenticationBytes)

	case privateSDeviceKey.Signer == nil && privateSDeviceKey.Agreer != nil:
		return newTaggedDeviceAuth()

	default:
		panic("invalid PrivateSDeviceKey")
	}
}

func newSignedDeviceAuth(
	rand io.Reader,
	signer *mdoc.PrivateKey,
	deviceAuthenticationBytes *cbor.TaggedEncodedCBOR,
) (*mdoc.DeviceAuth, error) {
	deviceAuth := &mdoc.DeviceAuth{DeviceSignature: &mdoc.DeviceSignature{
		Headers: cose.Headers{
			Protected: map[any]any{
				cose.HeaderLabelAlgorithm: signer.PublicKey.Algorithm,
			},
		},
	}}

	sign1 := (cose.Sign1Message)(*deviceAuth.DeviceSignature)
	sign1.Payload = deviceAuthenticationBytes.TaggedValue

	err := sign1.Sign(rand, []byte{}, mdoc.CoseSigner{Signer: signer.Signer})
	if err != nil {
		return nil, err
	}

	deviceAuth.DeviceSignature.Signature = sign1.Signature

	return deviceAuth, nil
}

func newTaggedDeviceAuth() (*mdoc.DeviceAuth, error) {
	return nil, mdoc.ErrMACAuthNotSupported
}
