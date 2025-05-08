package holder

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
	"io"
)

func NewDeviceAuth(
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	deviceAuthenticationBytes *mdoc.TaggedEncodedCBOR,
) (*mdoc.DeviceAuth, error) {
	signer := privateSDeviceKey.Signer()
	agreer := privateSDeviceKey.Agreer()

	switch {
	case signer != nil && agreer == nil:
		return newSignedDeviceAuth(rand, signer, deviceAuthenticationBytes)

	case signer == nil && agreer != nil:
		return newTaggedDeviceAuth()

	default:
		panic("invalid PrivateSDeviceKey")
	}
}

func newSignedDeviceAuth(
	rand io.Reader,
	signer mdoc.Signer,
	deviceAuthenticationBytes *mdoc.TaggedEncodedCBOR,
) (*mdoc.DeviceAuth, error) {
	deviceAuth := &mdoc.DeviceAuth{DeviceSignature: &mdoc.DeviceSignature{}}

	err := mdoc.coseSignDetached(rand, signer, (*cose.Sign1Message)(deviceAuth.DeviceSignature), deviceAuthenticationBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return deviceAuth, nil
}

func newTaggedDeviceAuth() (*mdoc.DeviceAuth, error) {
	return nil, mdoc.ErrMACAuthNotSupported
}
