package ed448

import (
	"github.com/alex-richards/go-mdoc"
	"github.com/cloudflare/circl/sign/ed448"
)

func NewPublicKey(publicKey ed448.PublicKey) (*mdoc.PublicKey, error) {
	return toPublicKey(publicKey)
}
