package holder

import (
	"github.com/alex-richards/go-mdoc"
)

type PrivateEDeviceKey interface {
	Agreer() mdoc.Agreer
	EDeviceKey() mdoc.PublicKey
}

type PrivateSDeviceKey interface {
	Signer() mdoc.Signer
	Agreer() mdoc.Agreer
	SDeviceKey() mdoc.PublicKey
}
