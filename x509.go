package mdoc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

var (
	ErrInvalidCertificate = errors.New("invalid certificate")
)

func x500VerifyChain(
	rootCertificates []*x509.Certificate,
	chain []*x509.Certificate,
	now time.Time,
	checkRootCertificate func(rootCertificate *x509.Certificate) error,
	checkIntermediateCertificate func(certificate *x509.Certificate, previous *x509.Certificate) error,
	checkLeafCertificate func(certificate *x509.Certificate, previous *x509.Certificate) error,
) (*x509.Certificate, error) {
	var err error

	if len(rootCertificates) == 0 {
		return nil, ErrNoRootCertificates
	}

	chainLen := len(chain)
	if chainLen == 0 {
		return nil, ErrEmptyChain
	}

	// find & check root certificate
	var rootCertificate *x509.Certificate
	{
		firstCertificate := chain[0]
		for _, candidateRootCertificate := range rootCertificates {
			if err = x500VerifyCertificateSignature(firstCertificate, candidateRootCertificate); err == nil {
				rootCertificate = candidateRootCertificate
				break
			}
		}
		if rootCertificate == nil {
			return nil, ErrInvalidCertificate
		}
		if checkRootCertificate != nil {
			if err = checkRootCertificate(rootCertificate); err != nil {
				return nil, err
			}
		}
	}

	// check chain signatures
	previousCertificate := rootCertificate
	for _, certificate := range chain {
		if err = x500VerifyCertificateSignature(certificate, previousCertificate); err != nil {
			return nil, err
		}
		previousCertificate = certificate
	}

	// run extra checks on chain
	leafCertificate := previousCertificate
	previousCertificate = rootCertificate
	for _, certificate := range chain {
		if certificate != leafCertificate {
			if checkIntermediateCertificate != nil {
				if err = checkIntermediateCertificate(certificate, previousCertificate); err != nil {
					return nil, err
				}
			}
		} else {
			if checkLeafCertificate != nil {
				if err = checkLeafCertificate(certificate, previousCertificate); err != nil {
					return nil, err
				}
			}
		}
		previousCertificate = certificate
	}

	// check leaf certificate is current
	if err = x500VerifyCertificateValidity(leafCertificate, now); err != nil {
		return nil, err
	}

	return leafCertificate, nil
}

func x500VerifyCertificateSignature(certificate *x509.Certificate, signer *x509.Certificate) error {
	// issuer matches signer's subject
	if !bytes.Equal(certificate.RawIssuer, signer.RawSubject) {
		return ErrInvalidCertificate
	}

	// cert validity is within signer's validity
	if signer.NotAfter.Before(certificate.NotAfter) {
		return ErrInvalidCertificate
	}
	if signer.NotBefore.After(certificate.NotBefore) {
		return ErrInvalidCertificate
	}

	// signature valid
	if err := certificate.CheckSignatureFrom(signer); err != nil {
		return err
	}

	return nil
}

func x500VerifyCertificateValidity(certificate *x509.Certificate, now time.Time) error {
	// cert currently valid
	if now.After(certificate.NotAfter) {
		return ErrInvalidCertificate
	}
	if now.Before(certificate.NotBefore) {
		return ErrInvalidCertificate
	}

	return nil
}
