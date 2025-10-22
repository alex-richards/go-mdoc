package ecdsa

import (
	"crypto/ecdsa"

	"github.com/alex-richards/go-mdoc"
)

func NewPublicKey(publicKey *ecdsa.PublicKey) (*mdoc.PublicKey, error) {
	return toPublicKey(publicKey)
}
