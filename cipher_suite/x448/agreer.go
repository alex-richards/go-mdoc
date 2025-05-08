package x448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/dh/x448"
	"io"
)

type Agreer x448.Key

func NewAgreer(rand io.Reader) (*Agreer, error) {
	var key Agreer
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	return &key, nil
}

func (a Agreer) Curve() mdoc.Curve {
	return mdoc.CurveX448
}

func (a Agreer) Agree(deviceKey *mdoc.PublicKey) ([]byte, error) {
	remote, err := fromMDocPublicKey(deviceKey)
	if err != nil {
		return nil, err
	}

	var shared x448.Key
	x448.Shared(&shared, (*x448.Key)(&a), remote)

	return shared[:], nil
}
