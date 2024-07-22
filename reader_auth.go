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
	ErrorMissingAlgorithmHeader = errors.New("missing algorithm header")
	ErrorUnsupportedAlgorithm   = errors.New("unsupported algorithm")
	ErrorEmptyChain             = errors.New("empty chan")
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
) (bool, error) {
	signatureAlgorithm, err := ra.Headers.Protected.Algorithm()
	if err != nil {
		return false, ErrorMissingAlgorithmHeader
	}

	var supportedCurve *Curve
	for _, candidateCurve := range CipherSuite1.Curves {
		if candidateCurve.coseAlg == signatureAlgorithm && candidateCurve.supportsReaderAuth {
			supportedCurve = &candidateCurve
			break
		}
	}
	if supportedCurve == nil {
		return false, ErrorUnsupportedAlgorithm
	}

	chain, err := X509Chain(ra.Headers.Unprotected)
	if err != nil {
		return false, err
	}

	chainLen := len(chain)
	if chainLen == 0 {
		return false, ErrorEmptyChain
	}

	{
		var prevCertificate *x509.Certificate
	Chain:
		for _, certificate := range chain {
			if prevCertificate == nil {
				for _, rootCertificate := range rootCertificates {
					err = certificate.CheckSignatureFrom(rootCertificate)
					if err == nil {
						continue Chain
					}
				}
				return false, err
			} else {
				err = certificate.CheckSignatureFrom(prevCertificate)
				if err == nil {
					return false, err
				}
			}
			prevCertificate = certificate
		}
	}

	signingCertificate := chain[chainLen-1]

	publicKey, ok := signingCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, ErrorUnsupportedAlgorithm
	}

	if publicKey.Curve != supportedCurve.ecdsaCurve {
		return false, ErrorUnsupportedAlgorithm
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, publicKey)
	if err != nil {
		return false, err
	}

	// gross, no external payload support, and no SigStructure not exported
	ra.Payload = readerAuthenticationBytes.taggedValue
	err = (*cose.Sign1Message)(ra).Verify(
		[]byte{},
		verifier,
	)
	if err != nil {
		return false, err
	}

	return true, nil
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
