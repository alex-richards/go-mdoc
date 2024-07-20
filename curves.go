package mdoc

import (
	"crypto/ecdh"
	"errors"

	"github.com/veraison/go-cose"
)

var ErrorUnsupportedCurve = errors.New("unsupported curve")

func NewCOSEKeyFromECDHPublicKey(key ecdh.PublicKey) (*cose.Key, error) {
	var coseAlg cose.Algorithm
	switch key.Curve() {
	case ecdh.P256():
		coseAlg = cose.AlgorithmES256
	case ecdh.P384():
		coseAlg = cose.AlgorithmES384
	case ecdh.P521():
		coseAlg = cose.AlgorithmES512
	default:
		return nil, ErrorUnsupportedCurve
	}

	bytes := key.Bytes()[1:]
	center := len(bytes) / 2

	return cose.NewKeyEC2(coseAlg, bytes[:center], bytes[center:], nil)
}

func NewECDHPublicKeyFromCOSEKey(key cose.Key) (*ecdh.PublicKey, error) {
	curve, x, y, _ := key.EC2()

	var ecdhCurve ecdh.Curve
	switch curve {
	case cose.CurveP256:
		ecdhCurve = ecdh.P256()
	case cose.CurveP384:
		ecdhCurve = ecdh.P384()
	case cose.CurveP521:
		ecdhCurve = ecdh.P521()
	default:
		return nil, ErrorUnsupportedCurve
	}

	point := make([]byte, 0, 1+len(x)+len(y))
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)

	return ecdhCurve.NewPublicKey(point)
}
