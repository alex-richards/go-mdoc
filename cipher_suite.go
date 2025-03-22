package mdoc

import (
	"errors"
	"io"
)

var (
	ErrUnsupportedCurve = errors.New("unsupported curve")
)

const (
	CipherSuiteVersion = 1
)

type Curve int

const (
	CurveP256 Curve = iota
	CurveP384
	CurveP521
	CurveX25519
	CurveX448
	CurveEd25519
	CurveEd448
	CurveBrainpoolP256r1
	CurveBrainpoolP320r1
	CurveBrainpoolP384r1
	CurveBrainpoolP512r1
)

var (
	SupportedCurves = [...]Curve{
		CurveP256,
		CurveP384,
		CurveP521,
		CurveX25519,
		CurveEd25519,
	}
)

type Signer interface {
	Curve() Curve
	Sign(rand io.Reader, data []byte) ([]byte, error)
}
