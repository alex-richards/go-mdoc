package mdoc

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

var (
	ErrUnsupportedDigestAlgorithm = errors.New("mdoc: unsupported digest algorithm")
)

type DigestAlgorithm string

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
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
		return nil, ErrUnsupportedDigestAlgorithm
	}
}

func (da *DigestAlgorithm) Sum(data []byte) ([]byte, error) {
	h, err := da.Hash()
	if err != nil {
		return nil, err
	}

	h.Reset()
	_, err = h.Write(data)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
