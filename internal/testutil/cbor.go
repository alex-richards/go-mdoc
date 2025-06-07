package testutil

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
)

func ExpectCBOR(t testing.TB, expected, got []byte) {
	t.Helper()

	diagExpected := DiagnoseCBOR(t, expected)
	diagGot := DiagnoseCBOR(t, got)

	if diff := cmp.Diff(diagExpected, diagGot); diff != "" {
		t.Fatalf("diff:\n%s\nexptected:\n%s\ngot:\n%s", diff, diagExpected, diagGot)
	}
}

func DiagnoseCBOR(t testing.TB, encoded []byte) string {
	t.Helper()

	diag, err := cbor.Diagnose(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return diag
}
