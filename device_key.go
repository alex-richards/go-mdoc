package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"io"
	"math/big"
)

type SDeviceKeyMode int

const (
	SDeviceKeyModeSign SDeviceKeyMode = iota
	SDeviceKeyModeMAC
)

type PrivateEDeviceKey interface {
	DeviceKey() (*DeviceKey, error)
	Curve() Curve
	Agree(*DeviceKey) ([]byte, error)
}

type PrivateSDeviceKey interface {
	PrivateEDeviceKey
	Signer
	Mode() SDeviceKeyMode
}

func NewSDeviceKey(rand io.Reader, curve Curve, mode SDeviceKeyMode) (PrivateSDeviceKey, error) {
	if mode == SDeviceKeyModeSign {
		var c elliptic.Curve
		var digestAlgorithm DigestAlgorithm
		switch curve {
		case CurveP256:
			c = elliptic.P256()
			digestAlgorithm = DigestAlgorithmSHA256
		case CurveP384:
			c = elliptic.P384()
			digestAlgorithm = DigestAlgorithmSHA384
		case CurveP521:
			c = elliptic.P521()
			digestAlgorithm = DigestAlgorithmSHA512

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
			key:             *key,
			curve:           curve,
			digestAlgorithm: digestAlgorithm,
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
			key:   key,
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
	switch dk.Type {
	case cose.KeyTypeOKP:
		switch curve, _ := dk.Params[cose.KeyLabelOKPCurve]; curve {
		case cose.CurveX25519:
			x, ok := dk.Params[cose.KeyLabelOKPX].([]byte)
			if !ok {
				return nil, ErrUnsupportedCurve
			}
			return ecdh.X25519().NewPublicKey(x)

		default:
			return nil, ErrUnsupportedCurve
		}

	case cose.KeyTypeEC2:
		publicKey, err := (*cose.Key)(dk).PublicKey()
		if err != nil {
			return nil, err
		}

		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, ErrUnsupportedAlgorithm
		}

		return ecdsaKey.ECDH()

	default:
		return nil, ErrUnsupportedCurve
	}
}

type privateDeviceKeyECDH struct {
	key   *ecdh.PrivateKey
	curve Curve
}

func (pdk *privateDeviceKeyECDH) DeviceKey() (*DeviceKey, error) {
	publicKey := pdk.key.PublicKey()

	var curve cose.Curve
	switch publicKey.Curve() {
	case ecdh.P256():
		curve = cose.CurveP256
	case ecdh.P384():
		curve = cose.CurveP384
	case ecdh.P521():
		curve = cose.CurveP521

	case ecdh.X25519():
		curve = cose.CurveX25519
		return &DeviceKey{
			Type: cose.KeyTypeOKP,
			Params: map[any]any{
				cose.KeyLabelOKPCurve: cose.CurveX25519,
				cose.KeyLabelOKPX:     publicKey.Bytes(),
			},
		}, nil

	default:
		return nil, ErrUnsupportedCurve
	}

	bytes := publicKey.Bytes()
	startY := len(bytes)/2 + 1
	x := bytes[1:startY]
	y := bytes[startY:]

	return &DeviceKey{
		Type: cose.KeyTypeEC2,
		Params: map[any]any{
			cose.KeyLabelEC2Curve: curve,
			cose.KeyLabelEC2X:     x,
			cose.KeyLabelEC2Y:     y,
		},
	}, nil
}

func (pdk *privateDeviceKeyECDH) Curve() Curve {
	return pdk.curve
}

func (pdk *privateDeviceKeyECDH) Agree(deviceKey *DeviceKey) ([]byte, error) {
	publicKey, err := deviceKey.publicKeyECDH()
	if err != nil {
		return nil, err
	}

	return pdk.key.ECDH(publicKey)
}

func (pdk *privateDeviceKeyECDH) Mode() SDeviceKeyMode {
	return SDeviceKeyModeMAC
}

func (pdk *privateDeviceKeyECDH) Sign(_ io.Reader, _ []byte) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

type privateDeviceKeyECDSA struct {
	key             ecdsa.PrivateKey
	curve           Curve
	digestAlgorithm DigestAlgorithm
}

func (pdk *privateDeviceKeyECDSA) DeviceKey() (*DeviceKey, error) {
	key, err := cose.NewKeyFromPublic(pdk.key.Public())
	if err != nil {
		return nil, err
	}

	return (*DeviceKey)(key), nil
}

func (pdk *privateDeviceKeyECDSA) Curve() Curve {
	return pdk.curve
}

func (pdk *privateDeviceKeyECDSA) Agree(_ *DeviceKey) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

func (pdk *privateDeviceKeyECDSA) Mode() SDeviceKeyMode {
	return SDeviceKeyModeSign
}

func (pdk *privateDeviceKeyECDSA) Sign(rand io.Reader, data []byte) ([]byte, error) {
	hash, err := pdk.digestAlgorithm.Hash()
	if err != nil {
		return nil, err
	}

	hash.Reset()
	hash.Write(data)
	digest := hash.Sum(nil)

	signatureASN1, err := ecdsa.SignASN1(rand, &pdk.key, digest)
	if err != nil {
		return nil, err
	}

	return asn1SignatureToConcat(pdk.curve, signatureASN1)
}

func asn1SignatureToConcat(curve Curve, signatureASN1 []byte) ([]byte, error) {
	type EcdsaSignature struct {
		R *big.Int
		S *big.Int
	}

	signatureECDSA := new(EcdsaSignature)
	rest, err := asn1.Unmarshal(signatureASN1, signatureECDSA)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("TODO: trailing data")
	}

	rBytes := signatureECDSA.R.Bytes()
	sBytes := signatureECDSA.S.Bytes()

	var size int
	switch curve {
	case CurveP256, CurveBrainpoolP256r1:
		size = 256
	case CurveP384, CurveBrainpoolP320r1:
		size = 384
	case CurveBrainpoolP384r1:
		size = 384
	case CurveP521, CurveBrainpoolP512r1:
		size = 521
	default:
		return nil, ErrUnsupportedCurve
	}
	byteSize := (size + 7) / 8

	concatSignature := make([]byte, byteSize*2)

	startR := byteSize - len(rBytes)
	startS := (byteSize * 2) - len(sBytes)

	copy(concatSignature[startR:], rBytes)
	copy(concatSignature[startS:], sBytes)

	return concatSignature, nil
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

func (pdk *privateDeviceKeyEdDSA) Agree(_ *DeviceKey) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

func (pdk *privateDeviceKeyEdDSA) Mode() SDeviceKeyMode {
	return SDeviceKeyModeSign
}

func (pdk *privateDeviceKeyEdDSA) Sign(_ io.Reader, data []byte) ([]byte, error) {
	return ed25519.Sign(pdk.key, data), nil
}
