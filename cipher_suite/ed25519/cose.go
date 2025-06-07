package ed25519

import (
	"crypto/ed25519"

	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
)

func toPublicKey(public ed25519.PublicKey) (*mdoc.PublicKey, error) {
	x := make([]byte, ed25519.PublicKeySize)
	copy(x, public)

	return &mdoc.PublicKey{
		Type: cose.KeyTypeOKP,
		Params: map[any]any{
			cose.KeyLabelOKPCurve: cose.CurveEd25519,
			cose.KeyLabelOKPX:     x,
		},
	}, nil
}

func fromPublicKey(key *mdoc.PublicKey) (ed25519.PublicKey, error) {
	if key.Type != cose.KeyTypeOKP {
		return nil, nil // TODO error
	}

	if key.Params[cose.KeyLabelOKPCurve] != cose.CurveEd25519 {
		return nil, nil // TODO error
	}

	x, ok := key.Params[cose.KeyLabelOKPX].([]byte)
	if !ok || len(x) != ed25519.PublicKeySize {
		return nil, nil // TODO error
	}

	public := make([]byte, ed25519.PublicKeySize)
	copy(public, x)
	return public, nil
}
