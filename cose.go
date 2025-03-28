package mdoc

import (
	"crypto/x509"
	"errors"
	"io"

	"github.com/veraison/go-cose"
)

var (
	ErrUnrecognisedHeaderType = errors.New("unrecognised type for header")
)

type coseSigner struct {
	Signer
	algorithm cose.Algorithm
}

func (cs *coseSigner) Algorithm() cose.Algorithm {
	return cs.algorithm
}

func newCoseSigner(signer Signer) (cose.Signer, error) {
	algorithm, err := signer.Curve().coseSignAlgorithm()
	if err != nil {
		return nil, err
	}

	return &coseSigner{
		signer,
		algorithm,
	}, nil
}

func (c Curve) coseSignAlgorithm() (cose.Algorithm, error) {
	switch c {
	case CurveP256, CurveBrainpoolP256r1:
		return cose.AlgorithmES256, nil
	case CurveP384, CurveBrainpoolP320r1, CurveBrainpoolP384r1:
		return cose.AlgorithmES384, nil
	case CurveP521, CurveBrainpoolP512r1:
		return cose.AlgorithmES512, nil
	case CurveEd448, CurveEd25519:
		return cose.AlgorithmEdDSA, nil
	default:
		return cose.AlgorithmReserved, ErrUnsupportedAlgorithm
	}
}

func coseSign(rand io.Reader, signer Signer, authStruct any) error {
	sign1Message, ok := authStruct.(*cose.UntaggedSign1Message)
	if !ok {
		panic("authStructure is not a UntaggedSign1Message")
	}

	coseSigner, err := newCoseSigner(signer)
	if err != nil {
		return err
	}

	return sign1Message.Sign(rand, []byte{}, coseSigner)
}

func coseSignDetached(rand io.Reader, signer Signer, authStruct any, payload []byte) error {
	sign1Message, ok := authStruct.(*cose.UntaggedSign1Message)
	if !ok {
		panic("authStructure is not a UntaggedSign1Message")
	}

	coseSigner, err := newCoseSigner(signer)
	if err != nil {
		return err
	}

	sign1Message.Payload = payload
	err = sign1Message.Sign(rand, []byte{}, coseSigner)
	sign1Message.Payload = nil

	return err
}

func coseX509Chain(from cose.UnprotectedHeader) ([]*x509.Certificate, error) {
	x509ChainHeader := from[cose.HeaderLabelX5Chain]

	switch x509ChainEncoded := x509ChainHeader.(type) {
	case []byte:
		cert, err := x509.ParseCertificate(x509ChainEncoded)
		if err != nil {
			return nil, err
		}

		return []*x509.Certificate{cert}, nil
	case [][]byte:
		certs := make([]*x509.Certificate, len(x509ChainEncoded))
		for i, certEncoded := range x509ChainEncoded {
			cert, err := x509.ParseCertificate(certEncoded)
			if err != nil {
				return nil, err
			}
			certs[i] = cert
		}
		return certs, nil
	default:
		return nil, ErrUnrecognisedHeaderType
	}
}
