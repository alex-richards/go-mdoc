package mdoc

import (
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestNewDeviceEngagement(t *testing.T) {
	_, err := NewDeviceEngagement(EDeviceKeyPublic)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeviceEngagementCBORRoundTrip(t *testing.T) {
	eDeviceKeyBytes, err := NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	peripheralServerUUID := uuid.New()

	deviceEngagement := DeviceEngagement{
		Version: "1.0",
		Security: Security{
			CipherSuiteIdentifier: 1,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		DeviceRetrievalMethods: []DeviceRetrievalMethod{
			{
				Type:    DeviceRetrievalMethodTypeBLE,
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

	deviceEngagementBytes, err := cbor.Marshal(&deviceEngagement)
	if err != nil {
		t.Fatal(err)
	}

	var deviceEngagementUnmarshalled DeviceEngagement
	if err = cbor.Unmarshal(deviceEngagementBytes, &deviceEngagementUnmarshalled); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		&deviceEngagement,
		&deviceEngagementUnmarshalled,
		cmp.FilterPath(func(p cmp.Path) bool {
			return p.Last().Type() == reflect.TypeOf(TaggedEncodedCBOR{})
		}, cmp.Ignore()),
	); diff != "" {
		t.Fatal(diff)
	}
}

func TestDeviceEngagementUnknownMethod(t *testing.T) {
	eDeviceKeyBytes, err := NewTaggedEncodedCBOR([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagement := DeviceEngagement{
		Version: "1.0",
		Security: Security{
			CipherSuiteIdentifier: 1,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		DeviceRetrievalMethods: []DeviceRetrievalMethod{
			{
				Type:    123,
				Version: 1,
			},
		},
	}

	deviceEngagementBytes, err := cbor.Marshal(&deviceEngagement)
	if err != nil {
		t.Fatal(err)
	}

	var deviceEngagementUnmarshalled DeviceEngagement
	if err = cbor.Unmarshal(deviceEngagementBytes, &deviceEngagementUnmarshalled); err == nil {
		t.Fatal("expected error")
	}
}
