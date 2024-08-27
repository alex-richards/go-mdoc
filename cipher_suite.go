package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/veraison/go-cose"
	"math/big"
)

var CipherSuite1 = CipherSuite{
	Version: 1,
	SupportedCurves: []*Curve{
		{
			name:          "P256",
			algorithmCose: cose.AlgorithmES256, // assumes no brainpool support
			curveCOSE:     cose.CurveP256,
			curveECDH:     ecdh.P256(),
			curveElliptic: elliptic.P256(),
		},
		{
			name:          "P384",
			algorithmCose: cose.AlgorithmES384, // assumes no brainpool support
			curveCOSE:     cose.CurveP384,
			curveECDH:     ecdh.P384(),
			curveElliptic: elliptic.P384(),
		},
		{
			name:          "P521",
			algorithmCose: cose.AlgorithmES512, // assumes no brainpool support
			curveCOSE:     cose.CurveP521,
			curveECDH:     ecdh.P521(),
			curveElliptic: elliptic.P521(),
		},
		// TODO x25519 supported for ECDH, but Ed25519 not supported for ECDSA
		// TODO no support for X448/Ed448
		// TODO no support for Brainpool
	},
}

type CipherSuite struct {
	Version         int
	SupportedCurves []*Curve
}

func (cs *CipherSuite) findCurveFromCOSEAlgorithm(algorithm cose.Algorithm) (*Curve, error) {
	return cs.findCurve(func(curve *Curve) bool {
		return algorithm == curve.algorithmCose
	})
}

func (cs *CipherSuite) findCurveFromCOSECurve(curveCOSE cose.Curve) (*Curve, error) {
	return cs.findCurve(func(curve *Curve) bool {
		return curveCOSE == curve.curveCOSE
	})
}

func (cs *CipherSuite) findCurveFromECDHCurve(curveECDH ecdh.Curve) (*Curve, error) {
	return cs.findCurve(func(curve *Curve) bool {
		return curveECDH == curve.curveECDH
	})
}

func (cs *CipherSuite) findCurveFromCurveElliptic(curveElliptic elliptic.Curve) (*Curve, error) {
	return cs.findCurve(func(curve *Curve) bool {
		return curveElliptic == curve.curveElliptic
	})
}

func (cs *CipherSuite) findCurve(filter func(curve *Curve) bool) (*Curve, error) {
	for _, curve := range cs.SupportedCurves {
		if filter(curve) {
			return curve, nil
		}
	}
	return nil, ErrUnsupportedAlgorithm
}

type Curve struct {
	name          string
	algorithmCose cose.Algorithm
	curveCOSE     cose.Curve
	curveECDH     ecdh.Curve
	curveElliptic elliptic.Curve
}

func (cs *CipherSuite) ecdhToCOSE(key *ecdh.PublicKey) (*cose.Key, error) {
	curveECDH := key.Curve()
	curve, err := cs.findCurveFromECDHCurve(curveECDH)
	if err != nil {
		return nil, err
	}

	bytes := key.Bytes()[1:]
	center := len(bytes) / 2
	return cose.NewKeyEC2(curve.algorithmCose, bytes[:center], bytes[center:], nil)
}

func (cs *CipherSuite) coseToECDH(key *cose.Key) (*ecdh.PublicKey, error) {
	c, x, y, _ := key.EC2()
	curve, err := cs.findCurveFromCOSECurve(c)
	if err != nil {
		return nil, err
	}

	lenX := len(x)
	point := make([]byte, 1+lenX+len(y))
	point[0] = 0x04

	copy(point[1:], x)
	copy(point[1+lenX:], y)

	return curve.curveECDH.NewPublicKey(point)
}

func (cs *CipherSuite) ecdsaToCOSE(key *ecdsa.PublicKey) (*cose.Key, error) {
	curveElliptic := key.Curve
	curve, err := cs.findCurveFromCurveElliptic(curveElliptic)
	if err != nil {
		return nil, err
	}

	return cose.NewKeyEC2(curve.algorithmCose, key.X.Bytes(), key.Y.Bytes(), nil)
}

func (cs *CipherSuite) coseToECDSA(key *cose.Key) (*ecdsa.PublicKey, error) {
	c, x, y, _ := key.EC2()
	curve, err := cs.findCurveFromCOSECurve(c)
	if err != nil {
		return nil, err
	}

	keyECDSA := &ecdsa.PublicKey{Curve: curve.curveElliptic, X: new(big.Int), Y: new(big.Int)}
	keyECDSA.X.SetBytes(x)
	keyECDSA.Y.SetBytes(y)
	return keyECDSA, nil
}
