package ed448

import (
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
)

// GeneratePrivateKey generates a new private key for use with go-mdoc.
func GeneratePrivateKey(rand io.Reader) (*mdoc.PrivateKey, error) {
	privateKey := make(ed448.PrivateKey, ed448.PrivateKeySize)
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(privateKey)
}

// NewPrivateKey wraps an existing private key for use with go-mdoc.
func NewPrivateKey(privateKey ed448.PrivateKey) (*mdoc.PrivateKey, error) {
	publicKey, err := toPublicKey(privateKey.Public().(ed448.PublicKey))
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    (signer)(privateKey),
		Agreer:    nil,
		PublicKey: *publicKey,
	}, nil
}

type signer ed448.PrivateKey

func (s signer) Curve() mdoc.Curve {
	return mdoc.CurveEd448
}

func (s signer) Sign(_ io.Reader, data []byte) ([]byte, error) {
	return ed448.Sign((ed448.PrivateKey)(s), data, ""), nil
}
