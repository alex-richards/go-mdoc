package mdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrMissingAlgorithmHeader = errors.New("missing algorithm header")
	ErrUnsupportedAlgorithm   = errors.New("unsupported algorithm")
	ErrEmptyChain             = errors.New("empty chan")
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
	now time.Time, // TODO check validity
	readerAuthenticationBytes *TaggedEncodedCBOR,
) error {
	signatureAlgorithm, err := ra.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	var supportedCurve *Curve
	for _, candidateCurve := range CipherSuite1.Curves {
		if candidateCurve.coseAlg == signatureAlgorithm && candidateCurve.supportsReaderAuth {
			supportedCurve = candidateCurve
			break
		}
	}
	if supportedCurve == nil {
		return ErrUnsupportedAlgorithm
	}

	chain, err := X509Chain(ra.Headers.Unprotected)
	if err != nil {
		return err
	}

	chainLen := len(chain)
	if chainLen == 0 {
		return ErrEmptyChain
	}

	firstCertificate := chain[0]
	for _, rootCertificate := range rootCertificates {
		err = firstCertificate.CheckSignatureFrom(rootCertificate)
		if err == nil {
			break // found our root cert
		}
	}
	if err != nil {
		return err
	}

	signingCertificate := firstCertificate
	for _, certificate := range chain[1:] {
		err = certificate.CheckSignatureFrom(signingCertificate)
		if err != nil {
			return err
		}
		signingCertificate = certificate
	}

	publicKey, ok := signingCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrUnsupportedAlgorithm
	}

	if publicKey.Curve != supportedCurve.ecdsaCurve {
		return ErrUnsupportedAlgorithm
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, publicKey)
	if err != nil {
		return err
	}

	err = (*cose.Sign1Message)(ra).VerifyDetached(
		readerAuthenticationBytes.TaggedValue,
		[]byte{},
		verifier,
	)
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
