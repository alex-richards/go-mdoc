package testutil

import (
	"io"
	"math/rand"
	"testing"
)

func NewDeterministicRand(t testing.TB) io.Reader {
	t.Helper()

	return rand.New(rand.NewSource(1234))
}
