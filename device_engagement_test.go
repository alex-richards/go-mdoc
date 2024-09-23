package mdoc

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDeviceEngagement_EDeviceKey(t *testing.T) {
	rand := NewDeterministicRand()

	peripheralServerUUID, err := NewUUID(rand)
	if err != nil {
		t.Fatal(err)
	}

	EDeviceKeyPrivate, err := NewEDeviceKey(rand, CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	EDeviceKey, err := EDeviceKeyPrivate.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagement, err := NewDeviceEngagementBLE(EDeviceKey, nil, peripheralServerUUID)
	if err != nil {
		t.Fatal(err)
	}

	EDeviceKeyOut, err := deviceEngagement.EDeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(*EDeviceKey, *EDeviceKeyOut); diff != "" {
		t.Fatal(diff)
	}
}

