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
	if len(chain) == 0 {
		return ErrNoRootCertificates
	}

	chainLen := len(chain)
	if chainLen == 0 {
		return ErrEmptyChain
	}

	var rootCertificate *x509.Certificate
	var previousCertificate *x509.Certificate

	{
		firstCertificate := chain[0]
		for _, candidateRootCertificate := range rootCertificates {
			if err = checkReaderAuthIntermediateCertificate(now, firstCertificate, candidateRootCertificate); err == nil {
				rootCertificate = candidateRootCertificate
				break
			}
		}
		if rootCertificate == nil {
			return ErrInvalidReaderAuthCertificate
		}
		previousCertificate = firstCertificate
	}

	{
		for _, certificate := range chain[1:] {
			err = checkReaderAuthIntermediateCertificate(now, certificate, previousCertificate)
			if err != nil {
				return err
			}
			previousCertificate = certificate
		}
	}

	readerAuthCertificate := previousCertificate
	if chainLen == 1 {
		if err = checkReaderAuthCertificate(readerAuthCertificate, rootCertificate); err != nil {
			return err
		}
	} else {
		if err = checkReaderAuthCertificate(readerAuthCertificate, chain[chainLen-2]); err != nil {
			return err
		}
	}

	publicKey, ok := readerAuthCertificate.PublicKey.(*ecdsa.PublicKey)
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

func checkReaderAuthIntermediateCertificate(now time.Time, certificate *x509.Certificate, signer *x509.Certificate) error {
	// issuer matches signer's subject
	if !bytes.Equal(certificate.RawIssuer, signer.RawSubject) {
		return ErrInvalidReaderAuthCertificate
	}

	// cert valid
	if now.After(certificate.NotAfter) {
		return ErrInvalidReaderAuthCertificate
	}
	if now.Before(certificate.NotBefore) {
		return ErrInvalidReaderAuthCertificate
	}

	// cert validity is within signer's validity
	if signer.NotAfter.Before(certificate.NotAfter) {
		return ErrInvalidReaderAuthCertificate
	}
	if signer.NotBefore.After(certificate.NotBefore) {
		return ErrInvalidReaderAuthCertificate
	}

	// signature valid
	err := certificate.CheckSignatureFrom(signer)
	if err != nil {
		return err
	}

	return nil
}

func checkReaderAuthCertificate(certificate *x509.Certificate, signer *x509.Certificate) error {
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

	// TODO signature algorithm

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
