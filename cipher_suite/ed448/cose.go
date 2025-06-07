package ed448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/veraison/go-cose"
)

func toPublicKey(public ed448.PublicKey) (*mdoc.PublicKey, error) {
	x := make([]byte, ed448.PublicKeySize)
	copy(x, public)

	return &mdoc.PublicKey{
		Type: cose.KeyTypeOKP,
		Params: map[any]any{
			cose.KeyLabelOKPCurve: cose.CurveX448,
			cose.KeyLabelOKPX:     x,
		},
	}, nil
}

func fromDeviceKey(deviceKey *mdoc.PublicKey) (ed448.PublicKey, error) {
	if deviceKey.Type != cose.KeyTypeOKP {
		return nil, nil // TODO error
	}

	if deviceKey.Params[cose.KeyLabelOKPCurve] != cose.CurveX448 {
		return nil, nil // TODO error
	}

	x, ok := deviceKey.Params[cose.KeyLabelOKPX].([]byte)
	if !ok || len(x) != ed448.PublicKeySize {
		return nil, nil // TODO error
	}

	public := make([]byte, ed448.PublicKeySize)
	copy(public, x)
	return public, nil
}
