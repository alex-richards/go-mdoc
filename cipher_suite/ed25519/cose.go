package ed25519

import (
	"crypto/ed25519"
	"github.com/alex-richards/go-mdoc"
	"github.com/veraison/go-cose"
)

func toMDocPublicKey(public ed25519.PublicKey) (*mdoc.PublicKey, error) {
	return &mdoc.PublicKey{
		Type: cose.KeyTypeOKP,
		Params: map[any]any{
			cose.KeyLabelOKPCurve: cose.CurveEd25519,
			cose.KeyLabelOKPX:     public[:],
		},
	}, nil
}

func fromMDocPublicKey(key *mdoc.PublicKey) (ed25519.PublicKey, error) {
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
