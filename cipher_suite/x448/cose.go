package x448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/veraison/go-cose"
)

func toPublicKey(public *x448.Key) (*mdoc.PublicKey, error) {
	x := make([]byte, len(public))
	copy(x, public[:])

	return &mdoc.PublicKey{
		Type: cose.KeyTypeOKP,
		Params: map[any]any{
			cose.KeyLabelOKPCurve: cose.CurveX448,
			cose.KeyLabelOKPX:     x,
		},
	}, nil
}

func fromPublicKey(deviceKey *mdoc.PublicKey) (*x448.Key, error) {
	if deviceKey.Type != cose.KeyTypeOKP {
		return nil, mdoc.ErrInvalidCOSE
	}

	if deviceKey.Params[cose.KeyLabelOKPCurve] != cose.CurveX448 {
		return nil, mdoc.ErrInvalidCOSE
	}

	x, ok := deviceKey.Params[cose.KeyLabelOKPX].([]byte)
	if !ok {
		return nil, mdoc.ErrInvalidCOSE
	}

	var key x448.Key
	if len(x) != len(key) {
		return nil, mdoc.ErrInvalidCOSE
	}

	copy(key[:], x)
	return &key, nil
}
