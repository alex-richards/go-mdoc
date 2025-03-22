package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrMissingAlgorithmHeader       = errors.New("missing algorithm header")
	ErrUnsupportedAlgorithm         = errors.New("unsupported algorithm")
	ErrNoRootCertificates           = errors.New("no root certificates")
	ErrEmptyChain                   = errors.New("empty chan")
	ErrInvalidReaderAuthCertificate = errors.New("invalid reader auth certificate")
)

type ReaderAuth cose.UntaggedSign1Message

func NewReaderAuth(
	rand io.Reader,
	readerAuthority ReaderAuthority,
	readerAuthentication ReaderAuthentication,
) (*ReaderAuth, error) {
	signer, err := newCoseSigner(readerAuthority)
	if err != nil {
		return nil, err
	}

	readerAuthenticationBytes, err := MarshalToNewTaggedEncodedCBOR(readerAuthentication)
	if err != nil {
		return nil, err
	}

	readerAuth := &ReaderAuth{
		Payload: readerAuthenticationBytes.TaggedValue,
	}

	err = (*cose.Sign1Message)(readerAuth).Sign(
		rand,
		[]byte{},
		signer,
	)
	if err != nil {
		return nil, err
	}

	readerAuth.Payload = nil

	return readerAuth, nil
}

func (ra *ReaderAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ra))
}
func (ra *ReaderAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ra))
}

func (ra *ReaderAuth) Verify(
	rootCertificates []*x509.Certificate,
	now time.Time,
	readerAuthentication ReaderAuthentication,
) error {
	chain, err := x509Chain(ra.Headers.Unprotected)
	if err != nil {
		return err
	}

	readerAuthCertificate, err := verifyChain(
		rootCertificates,
		chain,
		now,
		nil,
		nil,
		validateReaderAuthenticationCertificate,
	)
	if err != nil {
		return err
	}

	signatureAlgorithm, err := ra.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, readerAuthCertificate.PublicKey)
	if err != nil {
		return err
	}

	readerAuthenticationBytes, err := MarshalToNewTaggedEncodedCBOR(readerAuthentication)
	if err != nil {
		return err
	}

	sign1 := (cose.Sign1Message)(*ra)
	sign1.Payload = readerAuthenticationBytes.TaggedValue
	return sign1.Verify(
		[]byte{},
		verifier,
	)
}

func validateReaderAuthenticationCertificate(certificate *x509.Certificate, signer *x509.Certificate) error {
	if certificate.Version != 3 {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO serial number, max len 20 octets

	validityDuration := certificate.NotAfter.Sub(certificate.NotBefore)
	if validityDuration.Hours()/24 > 1187 {
		return ErrInvalidReaderAuthCertificate
	}

	if len(certificate.RawSubject) == 0 {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO subject public key info checks

	if !bytes.Equal(certificate.AuthorityKeyId, signer.SubjectKeyId) {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO subject key identifier check

	// TODO exclusive?
	if certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO issuer alt name

	extKeyUsage := certificate.UnknownExtKeyUsage
	if len(extKeyUsage) != 1 {
		return ErrInvalidReaderAuthCertificate
	}
	if !extKeyUsage[0].Equal(asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}) {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO CRL distribution points

	// TODO authority information access

	switch certificate.PublicKeyAlgorithm {
	case x509.ECDSA:
		_, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidReaderAuthCertificate
		}

	case x509.Ed25519:
		_, ok := certificate.PublicKey.(*ed25519.PublicKey)
		if !ok {
			return ErrInvalidReaderAuthCertificate
		}

	default:
		return ErrInvalidReaderAuthCertificate
	}

	return nil
}

type ReaderAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	ReaderAuthentication string
	SessionTranscript    SessionTranscript
	ItemsRequestBytes    TaggedEncodedCBOR
}

func NewReaderAuthentication(
	sessionTranscript SessionTranscript,
	itemsRequestBytes TaggedEncodedCBOR,
) *ReaderAuthentication {
	return &ReaderAuthentication{
		ReaderAuthentication: "ReaderAuthentication",
		SessionTranscript:    sessionTranscript,
		ItemsRequestBytes:    itemsRequestBytes,
	}
}
