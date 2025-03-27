package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"io"
)

type SDeviceKeyMode int

const (
	SDeviceKeyModeSign SDeviceKeyMode = iota
	SDeviceKeyModeMAC
)

type PrivateEDeviceKey interface {
	DeviceKey() (*DeviceKey, error)
	Curve() Curve
	Agree(DeviceKey) ([]byte, error)
}

type PrivateSDeviceKey interface {
	PrivateEDeviceKey
	Signer
	Mode() SDeviceKeyMode
}

func NewSDeviceKey(rand io.Reader, curve Curve, mode SDeviceKeyMode) (PrivateSDeviceKey, error) {
	if mode == SDeviceKeyModeSign {
		var c elliptic.Curve
		switch curve {
		case CurveP256:
			c = elliptic.P256()
		case CurveP384:
			c = elliptic.P384()
		case CurveP521:
			c = elliptic.P521()

		case CurveEd25519:
			_, key, err := ed25519.GenerateKey(rand)
			if err != nil {
				return nil, err
			}
			return &privateDeviceKeyEdDSA{
				key: key,
			}, nil

		default:
			return nil, ErrUnsupportedCurve
		}

		key, err := ecdsa.GenerateKey(c, rand)
		if err != nil {
			return nil, err
		}
		return &privateDeviceKeyECDSA{
			key:   *key,
			curve: curve,
		}, nil
	}

	if mode == SDeviceKeyModeMAC {
		var c ecdh.Curve
		switch curve {
		case CurveP256:
			c = ecdh.P256()
		case CurveP384:
			c = ecdh.P384()
		case CurveP521:
			c = ecdh.P521()
		case CurveX25519:
			c = ecdh.X25519()

		default:
			return nil, ErrUnsupportedCurve
		}

		key, err := c.GenerateKey(rand)
		if err != nil {
			return nil, err
		}
		return &privateDeviceKeyECDH{
			key:   *key,
			curve: curve,
		}, nil
	}

	return nil, ErrUnsupportedCurve
}

func NewEDeviceKey(rand io.Reader, curve Curve) (PrivateEDeviceKey, error) {
	return NewSDeviceKey(rand, curve, SDeviceKeyModeMAC)
}

type DeviceKey cose.Key

func (dk *DeviceKey) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.Key)(dk))
}

func (dk *DeviceKey) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.Key)(dk))
}

func (dk *DeviceKey) publicKeyECDH() (*ecdh.PublicKey, error) {
	publicKey, err := (*cose.Key)(dk).PublicKey()
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := publicKey.(ecdsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	return ecdsaKey.ECDH()
}

type privateDeviceKeyECDH struct {
	key   ecdh.PrivateKey
	curve Curve
}

func (pdk *privateDeviceKeyECDH) DeviceKey() (*DeviceKey, error) {
	key, err := cose.NewKeyFromPublic(pdk.key.Public())
	if err != nil {
		return nil, err
	}

	return (*DeviceKey)(key), nil
}

func (pdk *privateDeviceKeyECDH) Curve() Curve {
	return pdk.curve
}

func (pdk *privateDeviceKeyECDH) Agree(deviceKey DeviceKey) ([]byte, error) {
	publicKey, err := (*cose.Key)(&deviceKey).PublicKey()
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := publicKey.(ecdsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	ecdhKey, err := ecdsaKey.ECDH()
	if err != nil {
		return nil, err
	}

	return pdk.key.ECDH(ecdhKey)
}

func (pdk *privateDeviceKeyECDH) Mode() SDeviceKeyMode {
	return SDeviceKeyModeMAC
}

func (pdk *privateDeviceKeyECDH) Sign(_ io.Reader, _ []byte) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

type privateDeviceKeyECDSA struct {
	key   ecdsa.PrivateKey
	curve Curve
}

func (pdk *privateDeviceKeyECDSA) DeviceKey() (*DeviceKey, error) {
	key, err := cose.NewKeyFromPrivate(pdk.key.Public())
	if err != nil {
		return nil, err
	}

	return (*DeviceKey)(key), nil
}

func (pdk *privateDeviceKeyECDSA) Curve() Curve {
	return pdk.curve
}

func (pdk *privateDeviceKeyECDSA) Agree(_ DeviceKey) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

func (pdk *privateDeviceKeyECDSA) Mode() SDeviceKeyMode {
	return SDeviceKeyModeSign
}

func (pdk *privateDeviceKeyECDSA) Sign(rand io.Reader, data []byte) ([]byte, error) {
	panic("TODO") // TODO
}

type privateDeviceKeyEdDSA struct {
	key ed25519.PrivateKey
}

func (pdk *privateDeviceKeyEdDSA) DeviceKey() (*DeviceKey, error) {
	key, err := cose.NewKeyFromPublic(pdk.key.Public())
	if err != nil {
		return nil, err
	}

	return (*DeviceKey)(key), nil
}

func (pdk *privateDeviceKeyEdDSA) Curve() Curve {
	return CurveEd25519
}

func (pdk *privateDeviceKeyEdDSA) Agree(_ DeviceKey) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

func (pdk *privateDeviceKeyEdDSA) Mode() SDeviceKeyMode {
	return SDeviceKeyModeSign
}

func (pdk *privateDeviceKeyEdDSA) Sign(_ io.Reader, data []byte) ([]byte, error) {
	return ed25519.Sign(pdk.key, data), nil
}
