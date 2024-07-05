package mdoc

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"
)

func TestNewDeviceEngagement(t *testing.T) {
    eDeviceKey, err := cose.NewKeyEC2(
        cose.AlgorithmES256,
        make([]byte, 32),
        make([]byte, 32),
        []byte{1,2,3,4},
    )
    if err != nil {
        t.Fatal(err)
    }

    deviceEngagement, err := NewDeviceEngagement(eDeviceKey)
    if err != nil {
        t.Fatal(err)
    }

    eDeviceKeyUnmarshalled, err := deviceEngagement.EDeviceKey()
    if err != nil {
        t.Fatal(err)
    }

    if diff := cmp.Diff(eDeviceKey, eDeviceKeyUnmarshalled); diff != "" {
        t.Fatal(diff)
    }
}

func TestDeviceEngagementMarshalRoundTrip(t *testing.T) {
    peripheralServerUUID := uuid.New()
    deviceEngagement := DeviceEngagement {
        Version: "1.0",
        Security: Security{
            CipherSuiteIdentifier: 1,
            EDeviceKeyBytes: []byte{1,2,3,4},
        },
        DeviceRetrievalMethods: []DeviceRetrievalMethod{
            {
                Type: 2,
                Version: 1,
                RetrievalOptions: BleOptions{
                    SupportsPeripheralServer: true,
                    SupportsCentralClient: false,
                    PeripheralServerUUID: &peripheralServerUUID,
                    CentralClientUUID: nil,
                    PeripheralServerDeviceAddress: []byte{1,2,3,4},
                },
            },
        },
    }

    deviceEngagementMarshalled, err := cbor.Marshal(deviceEngagement)
    if err != nil { 
        t.Fatal(err)
    }

    var deviceEngagementUnmarshalled DeviceEngagement
    if err = cbor.Unmarshal(deviceEngagementMarshalled, &deviceEngagementUnmarshalled); err != nil {
        t.Fatal(err)
    }

    if diff := cmp.Diff(deviceEngagement, deviceEngagementUnmarshalled); diff != "" {
        t.Fatalf("unmarshalled object does not match\n%s", diff)
    }
}

const specDeviceEngagementHex = 
    "a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa" +
    "444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6702818" +
    "30201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917"

func TestSpecDeviceEngagement(t *testing.T){
    specDeviceEngagementBytes, err := hex.DecodeString(specDeviceEngagementHex)
    if err != nil {
        t.Fatal(err)
    }

    var specDeviceEngagement DeviceEngagement
    if err = cbor.Unmarshal(specDeviceEngagementBytes, &specDeviceEngagement); err != nil {
        t.Fatal(err)
    }

    eDeviceKey, err := specDeviceEngagement.EDeviceKey()
    if err != nil {
        t.Fatal(err)
    }

    specX, err := hex.DecodeString("5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE")
    if err != nil {
        t.Fatal(err)
    }

    specY, err := hex.DecodeString("B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67")
    if err != nil {
        t.Fatal(err)
    }

    specEDeviceKey, err := cose.NewKeyEC2(cose.AlgorithmES256, specX, specY, nil)
    if err != nil {
        t.Fatal(err)
    }

    if diff := cmp.Diff(
        specEDeviceKey, 
        eDeviceKey, 
        cmp.FilterPath(
            func(p cmp.Path) bool {
                return p.String() == "Algorithm"
            },
            cmp.Ignore(),
        ),
    ); diff != "" {
        t.Fatal(diff)
    }
}

