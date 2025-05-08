package reader

import (
	"github.com/alex-richards/go-mdoc"
	"io"
)

func NewAuthenticatedDocRequest(
	rand io.Reader,
	readerAuthority ReaderAuthority,
	itemsRequest *mdoc.ItemsRequest,
	sessionTranscript *mdoc.SessionTranscript,
) (*mdoc.DocRequest, error) {
	docRequest, err := mdoc.NewDocRequest(itemsRequest)
	if err != nil {
		return nil, err
	}

	readerAuthenticationBytes, err := mdoc.NewReaderAuthenticationBytes(sessionTranscript, &docRequest.ItemsRequestBytes)
	if err != nil {
		return nil, err
	}

	docRequest.ReaderAuth, err = NewReaderAuth(rand, readerAuthority, readerAuthenticationBytes)
	if err != nil {
		return nil, err
	}

	return docRequest, nil
}

func NewReaderAuth(
	rand io.Reader,
	readerAuthority ReaderAuthority,
	readerAuthenticationBytes *mdoc.TaggedEncodedCBOR,
) (*mdoc.ReaderAuth, error) {
	readerAuth := new(mdoc.ReaderAuth)

	err := mdoc.coseSignDetached(rand, readerAuthority.Signer(), readerAuth, readerAuthenticationBytes.TaggedValue)
	if err != nil {
		return nil, err
	}

	return readerAuth, nil
}
