package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/alex-richards/go-mdoc"
)

func GeneratePrivateKey(rand io.Reader) (*mdoc.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	pk, err := toPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    (signer)(privateKey),
		Agreer:    nil,
		PublicKey: *pk,
	}, nil
}

type signer ed25519.PrivateKey

func (s signer) Curve() mdoc.Curve {
	return mdoc.CurveEd25519
}

func (s signer) Sign(_ io.Reader, message []byte) ([]byte, error) {
	return ed25519.Sign((ed25519.PrivateKey)(s), message), nil
}
