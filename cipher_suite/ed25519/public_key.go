package ed25519

import (
	"crypto/ed25519"

	"github.com/alex-richards/go-mdoc"
)

func NewPublicKey(publicKey ed25519.PublicKey) (*mdoc.PublicKey, error) {
	return toPublicKey(publicKey)
}
