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
