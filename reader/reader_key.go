package reader

import (
	"github.com/alex-richards/go-mdoc"
)

type PrivateEReaderKey interface {
	Agreer() mdoc.Agreer
	EReaderKey() mdoc.PublicKey
}
