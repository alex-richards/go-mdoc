package spec

import (
	"testing"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/cipher_suite/ecdh"
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"github.com/google/go-cmp/cmp"
)

func Test_DeviceEngagement_EDeviceKey(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)
	peripheralServerUUID := testutil.NewUUID(t, rand)

	eDeviceKey, err := ecdh.GeneratePrivateKey(rand, mdoc.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagement, err := mdoc.NewDeviceEngagementBLE(&eDeviceKey.PublicKey, nil, peripheralServerUUID)
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKeyOut, err := deviceEngagement.EDeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(&eDeviceKey.PublicKey, eDeviceKeyOut); diff != "" {
		t.Fatal(diff)
	}
}
