package x448

import (
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/dh/x448"
)

// GeneratePrivateKey generates a new private key for use with go-mdoc.
func GeneratePrivateKey(rand io.Reader) (*mdoc.PrivateKey, error) {
	var privateKey x448.Key
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(&privateKey)
}

// NewPrivateKey wraps an existing private key for use with go-mdoc.
func NewPrivateKey(privateKey *x448.Key) (*mdoc.PrivateKey, error) {
	var publicKey x448.Key
	x448.KeyGen(&publicKey, privateKey)

	pk, err := toPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	return &mdoc.PrivateKey{
		Signer:    nil,
		Agreer:    (agreer)(*privateKey),
		PublicKey: *pk,
	}, nil
}

type agreer x448.Key

func (a agreer) Curve() mdoc.Curve {
	return mdoc.CurveX448
}

func (a agreer) Agree(deviceKey *mdoc.PublicKey) ([]byte, error) {
	remote, err := fromPublicKey(deviceKey)
	if err != nil {
		return nil, err
	}

	var shared x448.Key
	x448.Shared(&shared, (*x448.Key)(&a), remote)

	return shared[:], nil
}
