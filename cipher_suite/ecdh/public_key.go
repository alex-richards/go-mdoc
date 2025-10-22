package ecdh

import (
	"crypto/ecdh"

	"github.com/alex-richards/go-mdoc"
)

func NewPublicKey(publicKey *ecdh.PublicKey) (*mdoc.PublicKey, error) {
	return toPublicKey(publicKey)
}
