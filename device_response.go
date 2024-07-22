package mdoc

import (
	"github.com/fxamacker/cbor/v2"
)

type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []Document      `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         StatusCode      `cbor:"status"`
}

type StatusCode uint

const (
	StatusCodeOK                  StatusCode = 0
	StatusCodeGeneralError        StatusCode = 10
	StatusCodeCBORDecodingError   StatusCode = 11
	StatusCodeCBORValidationError StatusCode = 12
)

func NewDeviceResponse(
	documents []Document,
	documentErrors []DocumentError,
	status StatusCode,
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
type IssuerSignedItemBytess []TaggedEncodedCBOR
type IssuerSignedItems map[NameSpace][]IssuerSignedItem

func (ins IssuerNameSpaces) IssuerSignedItems() (IssuerSignedItems, error) {
	issuerSignedItemss := make(IssuerSignedItems)
	for nameSpace, issuerSignedItemBytess := range ins {
		issuerSignedItems := make([]IssuerSignedItem, len(issuerSignedItemBytess))
		for i, issuerSignedItemBytes := range issuerSignedItemBytess {
			issuerSignedItemBytesUntagged, err := issuerSignedItemBytes.UntaggedValue()
			if err != nil {
				return nil, err
			}

			var issuerSignedItem IssuerSignedItem
			if err = cbor.Unmarshal(issuerSignedItemBytesUntagged, &issuerSignedItem); err != nil {
				return nil, err
			}

			issuerSignedItems[i] = issuerSignedItem
		}
		issuerSignedItemss[nameSpace] = issuerSignedItems
	}
	return issuerSignedItemss, nil
}

type IssuerSignedItem struct {
	DigestID          uint                  `cbor:"digestID"`
	Random            []byte                `cbor:"random"`
	ElementIdentifier DataElementIdentifier `cbor:"elementIdentifier"`
	ElementValue      DataElementValue      `cbor:"elementValue"`
}

type DeviceSigned struct {
	NameSpacesBytes TaggedEncodedCBOR `cbor:"nameSpaces"`
	DeviceAuth      DeviceAuth        `cbor:"deviceAuth"`
}

func (ds *DeviceSigned) NameSpaces() (*DeviceNameSpaces, error) {
	nameSpacesBytesUntagged, err := ds.NameSpacesBytes.UntaggedValue()
	if err != nil {
		return nil, err
	}

	deviceNameSpaces := new(DeviceNameSpaces)
	if err = cbor.Unmarshal(nameSpacesBytesUntagged, deviceNameSpaces); err != nil {
		return nil, err
	}

	return deviceNameSpaces, nil
}

type DeviceNameSpaces map[NameSpace]DeviceSignedItems
type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type Errors map[NameSpace]ErrorItems
type ErrorItems map[DataElementIdentifier]ErrorCode
type ErrorCode int
