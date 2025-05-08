package mdoc

import (
	"github.com/alex-richards/go-mdoc/internal/testutil"
	"github.com/google/go-cmp/cmp"
	"testing"
)

func Test_DeviceEngagement_EDeviceKey(t *testing.T) {
	rand := testutil.NewDeterministicRand(t)
	peripheralServerUUID := testutil.NewUUID(t, rand)

	eDeviceKeyPrivate, err := NewEDeviceKey(rand, CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKey, err := eDeviceKeyPrivate.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagement, err := NewDeviceEngagementBLE(eDeviceKey, nil, peripheralServerUUID)
	if err != nil {
		t.Fatal(err)
	}

	eDeviceKeyOut, err := deviceEngagement.EDeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(eDeviceKey, eDeviceKeyOut); diff != "" {
		t.Fatal(diff)
	}
}
