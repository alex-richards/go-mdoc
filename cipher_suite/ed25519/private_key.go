package ed25519

import (
	"crypto/ed25519"
	"io"

	"github.com/alex-richards/go-mdoc"
)

// GeneratePrivateKey generates a new private key for use with go-mdoc.
func GeneratePrivateKey(rand io.Reader) (*mdoc.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return newPrivateKey(publicKey, privateKey)
}

// NewPrivateKey wraps an existing private key for use with go-mdoc.
func NewPrivateKey(privateKey ed25519.PrivateKey) (*mdoc.PrivateKey, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		panic("unreachable")
	}

	return newPrivateKey(publicKey, privateKey)
}

func newPrivateKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*mdoc.PrivateKey, error) {
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
