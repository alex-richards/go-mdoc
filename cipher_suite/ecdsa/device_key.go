package ecdsa

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/holder"
)

func NewPrivateSDeviceKey(signer Signer) (holder.PrivateSDeviceKey, error) {
	deviceKey, err := toMDocPublicKey(&signer.signer.PublicKey)
	if err != nil {
		return nil, err
	}

	return privateSDeviceKey{
		signer,
		*deviceKey,
	}, nil
}

type privateSDeviceKey struct {
	signer    Signer
	deviceKey mdoc.PublicKey
}

func (p privateSDeviceKey) Signer() mdoc.Signer {
	return p.signer
}

func (p privateSDeviceKey) Agreer() mdoc.Agreer {
	return nil
}

func (p privateSDeviceKey) SDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}
