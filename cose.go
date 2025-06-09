package mdoc

import (
	"errors"
	"io"

	"github.com/veraison/go-cose"
)

var (
	ErrInvalidCOSE = errors.New("mdoc: invalid cose")
)

type CoseSigner struct {
	Signer
}

func (cs CoseSigner) Algorithm() cose.Algorithm {
	return coseAlgorithm(cs.Signer.Curve())
}

func (cs CoseSigner) Sign(rand io.Reader, message []byte) ([]byte, error) {
	return cs.Signer.Sign(rand, message)
}

func coseAlgorithm(curve Curve) cose.Algorithm {
	switch curve {
	case CurveP256, CurveBrainpoolP256r1:
		return cose.AlgorithmES256
	case CurveP384, CurveBrainpoolP320r1, CurveBrainpoolP384r1:
		return cose.AlgorithmES384
	case CurveP521:
		return cose.AlgorithmES512
	case CurveEd448, CurveEd25519:
		return cose.AlgorithmEdDSA
	default:
		return cose.AlgorithmReserved
	}
}
