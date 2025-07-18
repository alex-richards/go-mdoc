package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"

	mdoccbor "github.com/alex-richards/go-mdoc/internal/cbor"
	mdoccose "github.com/alex-richards/go-mdoc/internal/cose"
	mdocx509 "github.com/alex-richards/go-mdoc/internal/x509"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const (
	ReaderAuthMaxAgeDays = 1187
)

var (
	ErrMissingAlgorithmHeader       = errors.New("mdoc: missing algorithm header")
	ErrNoRootCertificates           = errors.New("mdoc: no root certificates")
	ErrEmptyChain                   = errors.New("mdoc: empty chan")
	ErrInvalidReaderAuthCertificate = errors.New("mdoc: invalid reader auth certificate")
)

var (
	ReaderAuthenticationKeyUsage = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
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
	readerAuthenticationBytes *mdoccbor.TaggedEncodedCBOR,
) error {
	chain, err := mdoccose.X509Chain(ra.Headers.Unprotected)
	if err != nil {
		return err
	}

	readerAuthCertificate, err := mdocx509.VerifyChain(
		rootCertificates,
		chain,
		now,
		nil,
		nil,
		ValidateReaderAuthenticationCertificate,
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

func ValidateReaderAuthenticationCertificate(readerAuthCertificate *x509.Certificate, issuerCertificate *x509.Certificate) error {
	if readerAuthCertificate.Version != 3 {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO serial number, max len 20 octets

	{
		maxNotAfter := readerAuthCertificate.NotBefore.AddDate(0, 0, ReaderAuthMaxAgeDays)
		if readerAuthCertificate.NotAfter.Compare(maxNotAfter) > 0 {
			return ErrInvalidReaderAuthCertificate
		}
	}

	if len(readerAuthCertificate.RawSubject) == 0 {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO subject public key info checks

	// TODO signer != immediate parent
	//if !bytes.Equal(certificate.AuthorityKeyId, signer.SubjectKeyId) {
	//	return ErrInvalidReaderAuthCertificate
	//}

	// TODO subject key identifier check

	if readerAuthCertificate.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO issuer alt name

	{
		extKeyUsage := readerAuthCertificate.UnknownExtKeyUsage
		if len(extKeyUsage) != 1 {
			return ErrInvalidReaderAuthCertificate
		}
		if !extKeyUsage[0].Equal(ReaderAuthenticationKeyUsage) {
			return ErrInvalidReaderAuthCertificate
		}
	}

	// TODO CRL distribution points

	// TODO authority information access

	switch readerAuthCertificate.PublicKeyAlgorithm {
	case x509.ECDSA:
		_, ok := readerAuthCertificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidReaderAuthCertificate
		}

	case x509.Ed25519:
		_, ok := readerAuthCertificate.PublicKey.(*ed25519.PublicKey)
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
	ItemsRequestBytes    mdoccbor.TaggedEncodedCBOR
}

func NewReaderAuthenticationBytes(
	sessionTranscript *SessionTranscript,
	itemsRequestBytes *mdoccbor.TaggedEncodedCBOR,
) (*mdoccbor.TaggedEncodedCBOR, error) {
	return mdoccbor.MarshalToNewTaggedEncodedCBOR(NewReaderAuthentication(sessionTranscript, itemsRequestBytes))
}

func NewReaderAuthentication(
	sessionTranscript *SessionTranscript,
	itemsRequestBytes *mdoccbor.TaggedEncodedCBOR,
) *ReaderAuthentication {
	return &ReaderAuthentication{
		ReaderAuthentication: "ReaderAuthentication",
		SessionTranscript:    *sessionTranscript,
		ItemsRequestBytes:    *itemsRequestBytes,
	}
}
