package mdoc

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"testing"
)

func TestDeviceEngagement_EDeviceKey(t *testing.T) {
	rand := NewDeterministicRand()

	EDeviceKeyPrivate, err := NewEDeviceKey(rand, CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	EDeviceKey, err := EDeviceKeyPrivate.DeviceKey()
	if err != nil {
		t.Fatal(err)
	}

	deviceEngagement, err := NewDeviceEngagement(rand, EDeviceKey)
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

func TestDeviceRetrievalMethod_UnmarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		in      *DeviceRetrievalMethod
		inData  []byte
		want    *DeviceRetrievalMethod
		wantErr string
	}{
		{
			name: "valid wifi",
			in: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeWiFiAware,
				Version: 1,
				RetrievalOptions: WifiOptions{
					PassPhraseInfoPassPhrase:  "passphrase",
					ChannelInfoOperatingClass: 1,
					ChannelInfoChannelNumber:  2,
					BandInfoSupportedBands:    []byte{1, 2, 3, 4},
				},
			},
			want: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeWiFiAware,
				Version: 1,
				RetrievalOptions: WifiOptions{
					PassPhraseInfoPassPhrase:  "passphrase",
					ChannelInfoOperatingClass: 1,
					ChannelInfoChannelNumber:  2,
					BandInfoSupportedBands:    []byte{1, 2, 3, 4},
				},
			},
		},
		{
			name: "valid ble",
			in: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: BLEOptions{
					SupportsPeripheralServer:      true,
					SupportsCentralClient:         false,
					PeripheralServerUUID:          &uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
					CentralClientUUID:             nil,
					PeripheralServerDeviceAddress: nil,
				},
			},
			want: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: BLEOptions{
					SupportsPeripheralServer:      true,
					SupportsCentralClient:         false,
					PeripheralServerUUID:          &uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
					CentralClientUUID:             nil,
					PeripheralServerDeviceAddress: nil,
				},
			},
		},
		{
			name: "valid nfc",
			in: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeNFC,
				Version: 1,
				RetrievalOptions: NFCOptions{
					MaxLengthCommandData:  1234,
					MaxLengthResponseData: 5678,
				},
			},
			want: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeNFC,
				Version: 1,
				RetrievalOptions: NFCOptions{
					MaxLengthCommandData:  1234,
					MaxLengthResponseData: 5678,
				},
			},
		},
		{
			name: "mismatched types",
			in: &DeviceRetrievalMethod{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: WifiOptions{
					PassPhraseInfoPassPhrase:  "passphrase",
					ChannelInfoOperatingClass: 1,
					ChannelInfoChannelNumber:  2,
					BandInfoSupportedBands:    []byte{1, 2, 3, 4},
				},
			},
			wantErr: "cbor: cannot unmarshal UTF-8 text string into Go struct field mdoc.BLEOptions.0 of type bool",
		},
		{
			name: "unrecognised type",
			in: &DeviceRetrievalMethod{
				Type:             123,
				Version:          1,
				RetrievalOptions: WifiOptions{},
			},
			wantErr: "unrecognized retrieval method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			var data []byte

			if tt.inData != nil {
				data = tt.inData
			} else {
				data, err = cbor.Marshal(tt.in)
				if err != nil {
					t.Fatal(err)
				}
			}

			got := new(DeviceRetrievalMethod)
			err = cbor.Unmarshal(data, got)

			if err != nil && (err.Error() != tt.wantErr) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (tt.wantErr != "") {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); err == nil && diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
