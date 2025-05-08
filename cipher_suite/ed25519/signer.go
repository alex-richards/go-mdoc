package ed25519

import (
	"crypto/ed25519"
	"github.com/alex-richards/go-mdoc"
	"io"
)

type Signer ed25519.PrivateKey

func NewSigner(rand io.Reader) (*Signer, error) {
	_, private, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return (*Signer)(&private), nil
}

func (s Signer) Curve() mdoc.Curve {
	return mdoc.CurveEd25519
}

func (s Signer) Sign(_ io.Reader, data []byte) ([]byte, error) {
	return ed25519.Sign((ed25519.PrivateKey)(s), data), nil
}
