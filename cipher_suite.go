package mdoc

import (
	"errors"
)

var (
	ErrUnsupportedCurve = errors.New("mdoc: unsupported curve")
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
	case string(CurveP256),
		string(CurveP384),
		string(CurveP521),
		string(CurveX25519),
		string(CurveX448),
		string(CurveEd25519),
		string(CurveEd448),
		string(CurveBrainpoolP256r1),
		string(CurveBrainpoolP320r1),
		string(CurveBrainpoolP384r1),
		string(CurveBrainpoolP512r1):
		return Curve(name), nil
	default:
		return "", ErrUnsupportedCurve
	}
}

func (c Curve) Name() string {
	return (string)(c)
}
