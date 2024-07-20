package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/go-cose"
)

type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
}

func NewDeviceEngagement(eDeviceKey *cose.Key) (*DeviceEngagement, error) {
	security, err := newSecurity(eDeviceKey)
	if err != nil {
		return nil, err
	}

	return &DeviceEngagement{
		"1.0",
		*security,
		[]DeviceRetrievalMethod{
			newBleDeviceRetrievalMethod(),
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

func newSecurity(eDeviceKey *cose.Key) (*Security, error) {
	eDeviceKeyBytesUntagged, err := cbor.Marshal(eDeviceKey)
	if err != nil {
		return nil, err
	}

	eDeviceKeyBytes, err := NewTaggedEncodedCBOR(eDeviceKeyBytesUntagged)
	if err != nil {
		return nil, err
	}

	return &Security{
		CipherSuiteIdentifier: 1,
		EDeviceKeyBytes:       *eDeviceKeyBytes,
	}, nil
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

func newBleDeviceRetrievalMethod() DeviceRetrievalMethod {
	peripheralServerUUID := uuid.New()
	centralClientUUID := uuid.New()
	return DeviceRetrievalMethod{
		Type:    2,
		Version: 1,
		RetrievalOptions: BleOptions{
			SupportsPeripheralServer: true,
			SupportsCentralClient:    true,
			PeripheralServerUUID:     &peripheralServerUUID,
			CentralClientUUID:        &centralClientUUID,
		},
	}
}

func (deviceRetrievalMethod *DeviceRetrievalMethod) UnmarshalCBOR(data []byte) error {
	intermediateDeviceRetreievalMethod := new(intermediateDeviceRetreievalMethod)
	err := cbor.Unmarshal(data, intermediateDeviceRetreievalMethod)
	if err != nil {
		return err
	}

	switch intermediateDeviceRetreievalMethod.Type {
	case 2:
		bleOptions := BleOptions{}
		err = cbor.Unmarshal(intermediateDeviceRetreievalMethod.RetrievalOptions, &bleOptions)
		if err != nil {
			return err
		}
		deviceRetrievalMethod.RetrievalOptions = bleOptions

	default:
		return &ErrorUnreccognisedReterevalMethod{Type: intermediateDeviceRetreievalMethod.Type}
	}

	deviceRetrievalMethod.Type = intermediateDeviceRetreievalMethod.Type
	deviceRetrievalMethod.Version = intermediateDeviceRetreievalMethod.Version

	return nil
}

type ErrorUnreccognisedReterevalMethod struct {
	Type uint
}

func (err *ErrorUnreccognisedReterevalMethod) Error() string {
	return fmt.Sprintf("DeviceRetrievalMethod - no unmashaller for type %d", err.Type)
}

type RetrievalOptions interface{}

type BleOptions struct {
	SupportsPeripheralServer      bool       `cbor:"0,keyasint"`
	SupportsCentralClient         bool       `cbor:"1,keyasint"`
	PeripheralServerUUID          *uuid.UUID `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *uuid.UUID `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress []byte     `cbor:"20,keyasint,omitempty"`
}
