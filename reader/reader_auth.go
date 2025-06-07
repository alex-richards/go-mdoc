package reader

import (
	"io"

	"github.com/alex-richards/go-mdoc"
	"github.com/alex-richards/go-mdoc/internal/cbor"
	"github.com/veraison/go-cose"
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
	readerAuthenticationBytes *cbor.TaggedEncodedCBOR,
) (*mdoc.ReaderAuth, error) {
	readerAuth := new(mdoc.ReaderAuth)

	sign1 := (cose.Sign1Message)(*readerAuth)
	sign1.Payload = readerAuthenticationBytes.TaggedValue

	err := sign1.Sign(rand, []byte{}, mdoc.CoseSigner{readerAuthority.Signer})
	if err != nil {
		return nil, err
	}

	readerAuth.Signature = sign1.Signature
	return readerAuth, nil
}
