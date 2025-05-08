package ecdh

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/holder"
)

func NewPrivateEDeviceKey(agreer Agreer) (holder.PrivateEDeviceKey, error) {
	return newPrivateDeviceKey(agreer)
}

func NewPrivateSDeviceKey(agreer Agreer) (holder.PrivateSDeviceKey, error) {
	return newPrivateDeviceKey(agreer)
}

func newPrivateDeviceKey(agreer Agreer) (*privateDeviceKey, error) {
	deviceKey, err := toMDocPublicKey(agreer.agreer.PublicKey())
	if err != nil {
		return nil, err
	}

	return &privateDeviceKey{
		agreer,
		*deviceKey,
	}, nil
}

type privateDeviceKey struct {
	agreer    Agreer
	deviceKey mdoc.PublicKey
}

func (p *privateDeviceKey) Signer() mdoc.Signer {
	return nil
}

func (p *privateDeviceKey) Agreer() mdoc.Agreer {
	return p.Agreer()
}

func (p *privateDeviceKey) EDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}

func (p *privateDeviceKey) SDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}
