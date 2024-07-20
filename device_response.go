package mdoc

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const (
	StatusCodeOK                  = 0
	StatusCodeGeneralError        = 10
	StatusCodeCBORDecodingError   = 11
	StatusCodeCBORValidationError = 12
)

type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []Document      `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         uint            `cbor:"status"`
}

func NewDeviceResponse(
	documents []Document,
	documentErrors []DocumentError,
	status uint,
) *DeviceResponse {
	return &DeviceResponse{
		"1.0",
		documents,
		documentErrors,
		status,
	}
}

type DocumentError map[DocType]ErrorCode

type Document struct {
	DocType      DocType      `cbor:"docType"`
	IssuerSigned IssuerSigned `cbor:"issuerSigned"`
	DeviceSigned DeviceSigned `cbor:"deviceSigned"`
	Errors       Errors       `cbor:"errors,omitempty"`
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth IssuerAuth       `cbor:"issuerAuth"`
}

type IssuerNameSpaces map[NameSpace]IssuerSignedItemBytess
type IssuerSignedItemBytess []IssuerSignedItemBytes
type IssuerSignedItems map[NameSpace][]IssuerSignedItem

func (ins IssuerNameSpaces) IssuerSignedItems() (IssuerSignedItems, error) {
	issuerSignedItemss := make(IssuerSignedItems)
	for nameSpace, issuerSignedItemBytess := range ins {
		if issuerSignedItemBytess == nil {
			return nil, errors.New("TODO")
		}
		issuerSignedItems := make([]IssuerSignedItem, len(issuerSignedItemBytess))
		for i, issuerSignedItemBytes := range issuerSignedItemBytess {
			var issuerSignedItem IssuerSignedItem
			err := cbor.Unmarshal(issuerSignedItemBytes, &issuerSignedItem)
			if err != nil {
				return nil, err
			}
			issuerSignedItems[i] = issuerSignedItem
		}
		issuerSignedItemss[nameSpace] = issuerSignedItems
	}
	return issuerSignedItemss, nil
}

type IssuerSignedItemBytes TaggedEncodedCBOR
type IssuerSignedItem struct {
	DigestID          uint                  `cbor:"digestID"`
	Random            []byte                `cbor:"random"`
	ElementIdentifier DataElementIdentifier `cbor:"elementIdentifier"`
	ElementValue      DataElementValue      `cbor:"elementValue"`
}

type DeviceSigned struct {
	NameSpacesBytes DeviceNameSpacesBytes `cbor:"nameSpaces"`
	DeviceAuth      DeviceAuth            `cbor:"deviceAuth"`
}

func (ds *DeviceSigned) NameSpaces() (DeviceNameSpaces, error) {
	deviceNameSpaces := make(DeviceNameSpaces)
	err := cbor.Unmarshal(ds.NameSpacesBytes, &deviceNameSpaces)
	if err != nil {
		return nil, err
	}
	return deviceNameSpaces, nil
}

type DeviceNameSpacesBytes TaggedEncodedCBOR
type DeviceNameSpaces map[NameSpace]DeviceSignedItems
type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type Errors map[NameSpace]ErrorItems
type ErrorItems map[DataElementIdentifier]ErrorCode
type ErrorCode int
