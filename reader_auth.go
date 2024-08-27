package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
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

func (ra *ReaderAuth) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ra))
}
func (ra *ReaderAuth) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ra))
}

func (ra *ReaderAuth) Verify(
	readerAuthenticationBytes *TaggedEncodedCBOR,
	rootCertificates []*x509.Certificate,
	now time.Time,
) error {
	signatureAlgorithm, err := ra.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	curve, err := CipherSuite1.findCurveFromCOSEAlgorithm(signatureAlgorithm)
	if err != nil {
		return err
	}

	chain, err := x509Chain(ra.Headers.Unprotected)
	if err != nil {
		return err
	}

	readerAuthenticationCertificate, err := verifyChain(
		rootCertificates,
		chain,
		now,
		nil,
		nil,
		checkReaderAuthenticationCertificate,
	)
	if err != nil {
		return err
	}

	publicKey, ok := readerAuthenticationCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedAlgorithm
	}

	if publicKey.Curve != curve.curveElliptic {
		return ErrUnsupportedAlgorithm
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, publicKey)
	if err != nil {
		return err
	}

	return (*cose.Sign1Message)(ra).VerifyDetached(
		readerAuthenticationBytes.TaggedValue,
		[]byte{},
		verifier,
	)
}

func checkReaderAuthenticationCertificate(certificate *x509.Certificate, signer *x509.Certificate) error {
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
	if len(extKeyUsage) == 0 {
		return ErrInvalidReaderAuthCertificate
	}
	if !extKeyUsage[0].Equal(asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}) {
		return ErrInvalidReaderAuthCertificate
	}

	// TODO CRL distribution points

	// TODO authority information access

	// TODO add EdDSA support
	if certificate.PublicKeyAlgorithm != x509.ECDSA {
		return ErrUnsupportedAlgorithm
	}

	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedAlgorithm
	}

	// TODO no brainpool support?
	_, err := CipherSuite1.findCurveFromCurveElliptic(publicKey.Curve)
	if err != nil {
		return err
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
