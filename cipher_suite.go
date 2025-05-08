package mdoc

import (
	"errors"
	"io"
)

var (
	ErrUnsupportedCurve     = errors.New("mdoc: unsupported curve")
	ErrUnsupportedAlgorithm = errors.New("mdoc: unsupported algorithm")
)

const (
	CipherSuiteVersion = 1
)

type Curve string

const (
	CurveP256            Curve = "P256"
	CurveP384            Curve = "P384"
	CurveP521            Curve = "P521"
	CurveX25519          Curve = "X25519"
	CurveX448            Curve = "X448"
	CurveEd25519         Curve = "Ed25519"
	CurveEd448           Curve = "Ed448"
	CurveBrainpoolP256r1 Curve = "brainpoolP256r1"
	CurveBrainpoolP320r1 Curve = "brainpoolP320r1"
	CurveBrainpoolP384r1 Curve = "brainpoolP384r1"
	CurveBrainpoolP512r1 Curve = "brainpoolP512r1"
)

func CurveFromName(name string) (Curve, error) {
	switch name {
	case string(CurveP256):
		return CurveP256, nil
	case string(CurveP384):
		return CurveP384, nil
	case string(CurveP521):
		return CurveP521, nil
	case string(CurveX25519):
		return CurveX25519, nil
	case string(CurveX448):
		return CurveX448, nil
	case string(CurveEd25519):
		return CurveEd25519, nil
	case string(CurveEd448):
		return CurveEd448, nil
	case string(CurveBrainpoolP256r1):
		return CurveBrainpoolP256r1, nil
	case string(CurveBrainpoolP320r1):
		return CurveBrainpoolP320r1, nil
	case string(CurveBrainpoolP384r1):
		return CurveBrainpoolP384r1, nil
	case string(CurveBrainpoolP512r1):
		return CurveBrainpoolP512r1, nil
	default:
		return "", ErrUnsupportedCurve
	}
}

func (c Curve) Name() string {
	return (string)(c)
}

type Signer interface {
	Curve() Curve
	Sign(rand io.Reader, data []byte) ([]byte, error)
}

type Agreer interface {
	Curve() Curve
	Agree(publicKey *PublicKey) ([]byte, error)
}
