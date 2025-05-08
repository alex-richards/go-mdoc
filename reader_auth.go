package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	mdocX509 "github.com/alex-richards/go-mdoc/internal/x509"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrMissingAlgorithmHeader       = errors.New("mdoc: missing algorithm header")
	ErrNoRootCertificates           = errors.New("mdoc: no root certificates")
	ErrEmptyChain                   = errors.New("mdoc: empty chan")
	ErrInvalidReaderAuthCertificate = errors.New("mdoc: invalid reader auth certificate")
)

type ReaderAuth cose.UntaggedSign1Message

func (ra *ReaderAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ra))
}
func (ra *ReaderAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ra))
}

func (ra *ReaderAuth) Verify(
	rootCertificates []*x509.Certificate,
	now time.Time,
	readerAuthenticationBytes *TaggedEncodedCBOR,
) error {
	chain, err := coseX509Chain(ra.Headers.Unprotected)
	if err != nil {
		return err
	}

	readerAuthCertificate, err := mdocX509.VerifyChain(
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

func NewReaderAuthenticationBytes(
	sessionTranscript *SessionTranscript,
	itemsRequestBytes *TaggedEncodedCBOR,
) (*TaggedEncodedCBOR, error) {
	return MarshalToNewTaggedEncodedCBOR(NewReaderAuthentication(sessionTranscript, itemsRequestBytes))
}

func NewReaderAuthentication(
	sessionTranscript *SessionTranscript,
	itemsRequestBytes *TaggedEncodedCBOR,
) *ReaderAuthentication {
	return &ReaderAuthentication{
		ReaderAuthentication: "ReaderAuthentication",
		SessionTranscript:    *sessionTranscript,
		ItemsRequestBytes:    *itemsRequestBytes,
	}
}
