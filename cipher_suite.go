package mdoc

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"errors"

	"github.com/veraison/go-cose"
)

var (
	ErrorUnsupportedCurve = errors.New("unsupported curve")
)

var CipherSuite1 = CipherSuite{
	Version: 1,
	Curves: map[string]*Curve{
		"P265": {
			coseAlg:            cose.AlgorithmES256,
			coseCurve:          cose.CurveP256,
			ecdhCurve:          ecdh.P256(),
			ecdsaCurve:         elliptic.P256(),
			supportsReaderAuth: true,
		},
		"P384": {
			coseAlg:            cose.AlgorithmES384,
			coseCurve:          cose.CurveP384,
			ecdhCurve:          ecdh.P384(),
			ecdsaCurve:         elliptic.P384(),
			supportsReaderAuth: true,
		},
		"P521": {
			coseAlg:            cose.AlgorithmES512,
			coseCurve:          cose.CurveP521,
			ecdhCurve:          ecdh.P521(),
			ecdsaCurve:         elliptic.P521(),
			supportsReaderAuth: true,
		},
	},
}

type CipherSuite struct {
	Version int
	Curves  map[string]*Curve
}

type Curve struct {
	coseAlg   cose.Algorithm
	coseCurve cose.Curve

	ecdhCurve  ecdh.Curve
	ecdsaCurve elliptic.Curve

	supportsReaderAuth bool
}

func (cs *CipherSuite) ECDHToCOSE(key *ecdh.PublicKey) (*cose.Key, error) {
	keyCurve := key.Curve()

	for _, curve := range cs.Curves {
		if curve.ecdhCurve == keyCurve {
			bytes := key.Bytes()[1:]
			center := len(bytes) / 2
			return cose.NewKeyEC2(curve.coseAlg, bytes[:center], bytes[center:], nil)
		}
	}

	return nil, ErrorUnsupportedCurve
}

func (cs *CipherSuite) COSEToECDH(key *cose.Key) (*ecdh.PublicKey, error) {
	c, x, y, _ := key.EC2()

	for _, curve := range cs.Curves {
		if curve.coseAlg == key.Algorithm && curve.coseCurve == c {
			lenX := len(x)
			point := make([]byte, 1+lenX+len(y))
			point[0] = 0x04

			copy(point[1:], x)
			copy(point[1+lenX:], y)

			return curve.ecdhCurve.NewPublicKey(point)
		}
	}

	return nil, ErrorUnsupportedCurve
}
