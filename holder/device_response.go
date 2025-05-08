package holder

import (
	"github.com/alex-richards/go-mdoc"
	"io"
)

func CreateDeviceResponse(
	deviceRequest *mdoc.DeviceRequest,
	candidateIssuerSigneds map[mdoc.DocType]mdoc.IssuerSigned,
	candidateDeviceSigneds map[mdoc.DocType]map[mdoc.NameSpace]map[mdoc.DataElementIdentifier]any,
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	sessionTranscript *mdoc.SessionTranscript,
) (*mdoc.DeviceResponse, error) {
	documents := make([]mdoc.Document, 0)
	documentErrors := make([]mdoc.DocumentError, 0)

	for _, docRequest := range deviceRequest.DocRequests {
		itemsRequest, err := docRequest.ItemsRequest()
		if err != nil {
			return nil, err
		}

		candidateIssuerSigned, ok := candidateIssuerSigneds[itemsRequest.DocType]
		if !ok {
			documentErrors = append(documentErrors, mdoc.DocumentError{
				itemsRequest.DocType: mdoc.ErrorCodeDataNotReturned,
			})
			continue
		}

		requestNameSpaces := itemsRequest.NameSpaces
		documentIssuerNameSpaces, err := candidateIssuerSigned.NameSpaces.Filter(requestNameSpaces.Contains)
		if err != nil {
			return nil, err
		}

		documentIssuerSignedItems, err := documentIssuerNameSpaces.IssuerSignedItems()
		if err != nil {
			return nil, err
		}
		requestNameSpaces = itemsRequest.NameSpaces.Filter(documentIssuerSignedItems.Contains)

		documentDeviceNameSpaces := make(mdoc.DeviceNameSpaces)
		if len(candidateDeviceSigneds) > 0 && len(requestNameSpaces) > 0 {
			mobileSecurityObject, err := candidateIssuerSigned.IssuerAuth.MobileSecurityObject()
			if err != nil {
				return nil, err
			}

			keyAuthorizations := mobileSecurityObject.DeviceKeyInfo.KeyAuthorizations
			if keyAuthorizations != nil {
				authorizedDeviceNameSpaces := requestNameSpaces.Filter(keyAuthorizations.Contains)
				candidateDeviceSignedItems := candidateDeviceSigneds[itemsRequest.DocType]
				for authorizedDeviceNameSpace, authorizedDeviceDataElements := range authorizedDeviceNameSpaces {
					candidateDeviceNameSpace := candidateDeviceSignedItems[authorizedDeviceNameSpace]
					for authorizedDeviceDataElementIdentifier := range authorizedDeviceDataElements {
						candidateDeviceSignedItem, ok := candidateDeviceNameSpace[authorizedDeviceDataElementIdentifier]
						if ok {
							documentDeviceSignedItems, ok := documentDeviceNameSpaces[authorizedDeviceNameSpace]
							if !ok {
								documentDeviceSignedItems = make(mdoc.DeviceSignedItems)
								documentDeviceNameSpaces[authorizedDeviceNameSpace] = documentDeviceSignedItems
							}
							documentDeviceSignedItems[authorizedDeviceDataElementIdentifier] = candidateDeviceSignedItem
						}
					}
				}
			}
		}

		requestNameSpaces = requestNameSpaces.Filter(documentDeviceNameSpaces.Contains)
		var documentErrors *mdoc.Errors
		if len(requestNameSpaces) > 0 {
			*documentErrors = make(mdoc.Errors)
			for nameSpace, dataElements := range requestNameSpaces {
				(*documentErrors)[nameSpace] = make(mdoc.ErrorItems)
				for dataElement := range dataElements {
					(*documentErrors)[nameSpace][dataElement] = mdoc.ErrorCodeDataNotReturned
				}
			}
		}

		documentDeviceSigned, err := NewDeviceSigned(itemsRequest.DocType, documentDeviceNameSpaces, rand, privateSDeviceKey, sessionTranscript)
		if err != nil {
			return nil, err
		}

		documents = append(
			documents,
			mdoc.Document{
				DocType: itemsRequest.DocType,
				IssuerSigned: mdoc.IssuerSigned{
					NameSpaces: documentIssuerNameSpaces,
					IssuerAuth: candidateIssuerSigned.IssuerAuth,
				},
				DeviceSigned: *documentDeviceSigned,
				Errors:       documentErrors,
			},
		)
	}

	return mdoc.NewDeviceResponse(
		documents,
		documentErrors,
		mdoc.StatusCodeOK,
	), nil
}

func NewDeviceSigned(
	docType mdoc.DocType,
	nameSpaces mdoc.DeviceNameSpaces,
	rand io.Reader,
	privateSDeviceKey PrivateSDeviceKey,
	sessionTranscript *mdoc.SessionTranscript,
) (*mdoc.DeviceSigned, error) {
	nameSpacesBytes, err := mdoc.MarshalToNewTaggedEncodedCBOR(nameSpaces)
	if err != nil {
		return nil, err
	}

	deviceAuthenticationBytes, err := mdoc.NewDeviceAuthenticationBytes(sessionTranscript, docType, nameSpacesBytes)
	if err != nil {
		return nil, err
	}

	deviceAuth, err := NewDeviceAuth(rand, privateSDeviceKey, deviceAuthenticationBytes)
	if err != nil {
		return nil, err
	}

	return &mdoc.DeviceSigned{
		NameSpacesBytes: *nameSpacesBytes,
		DeviceAuth:      *deviceAuth,
	}, nil
}
