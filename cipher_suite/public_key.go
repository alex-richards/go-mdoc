package cipher_suite

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"

	"github.com/alex-richards/go-mdoc"
	mdocecdh "github.com/alex-richards/go-mdoc/cipher_suite/ecdh"
	mdocecdsa "github.com/alex-richards/go-mdoc/cipher_suite/ecdsa"
	mdoced25519 "github.com/alex-richards/go-mdoc/cipher_suite/ed25519"
	mdoced448 "github.com/alex-richards/go-mdoc/cipher_suite/ed448"
	mdocx448 "github.com/alex-richards/go-mdoc/cipher_suite/x448"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
)

var (
	ErrUnsupportedPublicKey = errors.New("mdoc: unsupported public key")
)

func NewPublicKey(publicKey crypto.PublicKey) (*mdoc.PublicKey, error) {
	switch pk := publicKey.(type) {
	case ecdsa.PublicKey:
		return mdocecdsa.NewPublicKey(&pk)
	case *ecdsa.PublicKey:
		return mdocecdsa.NewPublicKey(pk)
	case ed25519.PublicKey:
		return mdoced25519.NewPublicKey(pk)
	case ed448.PublicKey:
		return mdoced448.NewPublicKey(pk)
	case ecdh.PublicKey:
		return mdocecdh.NewPublicKey(&pk)
	case *ecdh.PublicKey:
		return mdocecdh.NewPublicKey(pk)
	case x448.Key:
		return mdocx448.NewPublicKey(&pk)
	case *x448.Key:
		return mdocx448.NewPublicKey(pk)
	default:
		return nil, ErrUnsupportedPublicKey
	}
}
