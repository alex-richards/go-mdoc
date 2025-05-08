package ed448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/holder"
	"github.com/cloudflare/circl/sign/ed448"
)

type privateSDeviceKey struct {
	signer    Signer
	deviceKey mdoc.PublicKey
}

func NewPrivateSDeviceKey(signer Signer) (holder.PrivateSDeviceKey, error) {
	public := (ed448.PrivateKey)(signer).Public().(ed448.PublicKey)

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
