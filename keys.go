package mdoc

import (
	"io"

	"github.com/veraison/go-cose"
)

type PrivateKey struct {
	Signer    Signer
	Agreer    Agreer
	PublicKey PublicKey
}

type Signer interface {
	Curve() Curve
	Sign(rand io.Reader, message []byte) ([]byte, error)
}

type Agreer interface {
	Curve() Curve
	Agree(publicKey *PublicKey) ([]byte, error)
}

type PublicKey cose.Key

func (p *PublicKey) MarshalCBOR() ([]byte, error) {
	return (*cose.Key)(p).MarshalCBOR()
}

func (p *PublicKey) UnmarshalCBOR(data []byte) error {
	return (*cose.Key)(p).UnmarshalCBOR(data)
}
