package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

func readCertificateFromPEM(reader io.Reader) (*x509.Certificate, error) {
	pemData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func writeCertificateToPEM(writer io.Writer, cert *x509.Certificate) error {
	return pem.Encode(writer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func readPrivateKeyFromPEM(reader io.Reader) (crypto.Signer, error) {
	pemData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a crypto.Signer")
	}

	return signer, nil
}

func writePrivateKeyToPEM(writer io.Writer, key *crypto.Signer) error {
	derData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	return pem.Encode(writer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derData,
	})
}
