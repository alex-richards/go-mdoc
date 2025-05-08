package testutil

import (
	"github.com/alex-richards/go-mdoc/util"
	"io"
	"testing"
)

func NewUUID(t testing.TB, rand io.Reader) *util.UUID {
	t.Helper()

	uuid, err := util.NewUUID(rand)
	if err != nil {
		t.Fatal(err)
	}

	return uuid
}
