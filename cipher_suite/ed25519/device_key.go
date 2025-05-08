package ed25519

import (
	"crypto/ed25519"
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/holder"
)

type privateSDeviceKey struct {
	signer    Signer
	deviceKey mdoc.PublicKey
}

func NewPrivateSDeviceKey(signer Signer) (holder.PrivateSDeviceKey, error) {
	public := (ed25519.PrivateKey)(signer).Public().(ed25519.PublicKey)

	deviceKey, err := toMDocPublicKey(public)
	if err != nil {
		return nil, err
	}

	return &privateSDeviceKey{
		signer,
		*deviceKey,
	}, nil
}

func (p *privateSDeviceKey) Signer() mdoc.Signer {
	return p.signer
}

func (p *privateSDeviceKey) Agreer() mdoc.Agreer {
	return nil
}

func (p *privateSDeviceKey) SDeviceKey() mdoc.PublicKey {
	return p.deviceKey
}
