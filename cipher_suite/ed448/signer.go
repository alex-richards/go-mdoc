package ed448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
	"io"
)

type Signer ed448.PrivateKey

func NewSigner(rand io.Reader) (Signer, error) {
	_, private, err := ed448.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	return (Signer)(private), nil
}

func (s Signer) Curve() mdoc.Curve {
	return mdoc.CurveEd448
}

func (s Signer) Sign(_ io.Reader, data []byte) ([]byte, error) {
	return ed448.Sign((ed448.PrivateKey)(s), data, ""), nil
}
