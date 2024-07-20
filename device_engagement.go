package mdoc

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"
)

const (
	DeviceRetrievalMethodTypeNFC       = 1
	DeviceRetrievalMethodTypeBLE       = 2
	DeviceRetrievalMethodTypeWiFiAware = 3
)

var ErrorUnreccognisedReterevalMethod = errors.New("unreccognised retreival method")

type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
}

func NewDeviceEngagement(eDeviceKey *cose.Key) (*DeviceEngagement, error) {
	eDeviceKeyBytesUntagged, err := cbor.Marshal(eDeviceKey)
	if err != nil {
		return nil, err
	}

	eDeviceKeyBytes, err := NewTaggedEncodedCBOR(eDeviceKeyBytesUntagged)
	if err != nil {
		return nil, err
	}

	peripheralServerUUID := uuid.New()
	centralClientUUID := uuid.New()
	return &DeviceEngagement{
		"1.0",
		Security{
			CipherSuiteIdentifier: 1,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		[]DeviceRetrievalMethod{
			{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: BleOptions{
					SupportsPeripheralServer: true,
					SupportsCentralClient:    true,
					PeripheralServerUUID:     &peripheralServerUUID,
					CentralClientUUID:        &centralClientUUID,
				},
			},
		},
	}, nil
}

func (de *DeviceEngagement) EDeviceKey() (*cose.Key, error) {
	eDeviceKeyBytesUntagged, err := de.Security.EDeviceKeyBytes.UntaggedValue()
	if err != nil {
		return nil, err
	}

	eDeviceKey := new(cose.Key)
	if err := cbor.Unmarshal(eDeviceKeyBytesUntagged, eDeviceKey); err != nil {
		return nil, err
	}

	return eDeviceKey, nil
}

type Security struct {
	_                     struct{} `cbor:",toarray"`
	CipherSuiteIdentifier int
	EDeviceKeyBytes       TaggedEncodedCBOR
}

type DeviceRetrievalMethod struct {
	_                struct{} `cbor:",toarray"`
	Type             uint
	Version          uint
	RetrievalOptions RetrievalOptions
}

type intermediateDeviceRetreievalMethod struct {
	_                struct{} `cbor:",toarray"`
	Type             uint
	Version          uint
	RetrievalOptions cbor.RawMessage
}

func (drm *DeviceRetrievalMethod) UnmarshalCBOR(data []byte) error {
	var intermediateDeviceRetreievalMethod intermediateDeviceRetreievalMethod
	if err := cbor.Unmarshal(data, &intermediateDeviceRetreievalMethod); err != nil {
		return err
	}

	switch intermediateDeviceRetreievalMethod.Type {
	case DeviceRetrievalMethodTypeBLE:
		var bleOptions BleOptions
		if err := cbor.Unmarshal(intermediateDeviceRetreievalMethod.RetrievalOptions, &bleOptions); err != nil {
			return err
		}
		drm.RetrievalOptions = bleOptions

	default:
		return ErrorUnreccognisedReterevalMethod
	}

	drm.Type = intermediateDeviceRetreievalMethod.Type
	drm.Version = intermediateDeviceRetreievalMethod.Version

	return nil
}

type RetrievalOptions interface{}

type BleOptions struct {
	SupportsPeripheralServer      bool       `cbor:"0,keyasint"`
	SupportsCentralClient         bool       `cbor:"1,keyasint"`
	PeripheralServerUUID          *uuid.UUID `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *uuid.UUID `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress []byte     `cbor:"20,keyasint,omitempty"`
}
