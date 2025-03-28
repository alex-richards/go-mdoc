package mdoc

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type DigestAlgorithm string

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
	DigestAlgorithmNone   DigestAlgorithm = "none"
)

func (da *DigestAlgorithm) Hash() (hash.Hash, error) {
	switch *da {
	case DigestAlgorithmSHA256:
		return sha256.New(), nil
	case DigestAlgorithmSHA384:
		return sha512.New384(), nil
	case DigestAlgorithmSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm: %v", da)
	}
}
