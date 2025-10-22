package x448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/dh/x448"
)

func NewPublicKey(publicKey *x448.Key) (*mdoc.PublicKey, error) {
	return toPublicKey(publicKey)
}
