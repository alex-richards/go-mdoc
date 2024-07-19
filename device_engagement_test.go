package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestNewDeviceEngagement(t *testing.T) {
	deviceEngagement, err := NewDeviceEngagement(EDeviceKeyPublic)
	if err != nil {
		t.Fatal(err)
	}

	if deviceEngagement == nil {
		t.Fatal()
	}
}

func TestDeviceEngagementCBORRoundTrip(t *testing.T) {
	peripheralServerUUID := uuid.New()
	deviceEngagement := &DeviceEngagement{
		Version: "1.0",
		Security: Security{
			CipherSuiteIdentifier: 1,
			EDeviceKeyBytes:       []byte{1, 2, 3, 4},
		},
		DeviceRetrievalMethods: []DeviceRetrievalMethod{
			{
				Type:    2,
				Version: 1,
				RetrievalOptions: BleOptions{
					SupportsPeripheralServer:      true,
					SupportsCentralClient:         false,
					PeripheralServerUUID:          &peripheralServerUUID,
					CentralClientUUID:             nil,
					PeripheralServerDeviceAddress: []byte{1, 2, 3, 4},
				},
			},
		},
	}

	deviceEngagementBytes, err := cbor.Marshal(deviceEngagement)
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagementUnmarshalled := new(DeviceEngagement)
	if err = cbor.Unmarshal(deviceEngagementBytes, deviceEngagementUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(deviceEngagement, deviceEngagementUnmarshalled); diff != "" {
		t.Fatal(diff)
	}
}

func TestDeviceEngagementUnknownMethod(t *testing.T) {
	deviceEngagement := &DeviceEngagement{
		Version: "1.0",
		Security: Security{
			CipherSuiteIdentifier: 1,
			EDeviceKeyBytes:       []byte{1, 2, 3, 4},
		},
		DeviceRetrievalMethods: []DeviceRetrievalMethod{
			{
				Type:    123,
				Version: 1,
			},
		},
	}

	deviceEngagementBytes, err := cbor.Marshal(deviceEngagement)
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagementUnmarshalled := new(DeviceEngagement)
	err = cbor.Unmarshal(deviceEngagementBytes, deviceEngagementUnmarshalled)
	if err == nil {
		t.Fatal()
	}

	errUnreccognisedReterevalMethod := err.(*ErrorUnreccognisedReterevalMethod)

	if errUnreccognisedReterevalMethod.Type != 123 {
		t.Fatal(errUnreccognisedReterevalMethod)
	}
}
