package x448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/holder"
	"github.com/cloudflare/circl/dh/x448"
)

type privateDeviceKey struct {
	agreer    Agreer
	deviceKey mdoc.PublicKey
}

func NewPrivateEDeviceKey(agreer Agreer) (holder.PrivateEDeviceKey, error) {
	return newPrivateDeviceKey(agreer)
}

func NewPrivateSDeviceKey(agreer Agreer) (holder.PrivateSDeviceKey, error) {
	return newPrivateDeviceKey(agreer)
}

func newPrivateDeviceKey(agreer Agreer) (*privateDeviceKey, error) {
	var public x448.Key
	x448.KeyGen(&public, (*x448.Key)(&agreer))

	deviceKey, err := toMDocPublicKey(&public)
	if err != nil {
		return nil, err
	}

	return &privateDeviceKey{
		agreer,
		*deviceKey,
	}, nil
}

func (p *privateDeviceKey) Signer() mdoc.Signer {
	return nil
}

func (p *privateDeviceKey) Agreer() mdoc.Agreer {
	return p.agreer
}

func (p *privateDeviceKey) EDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}

func (p *privateDeviceKey) SDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}
