package mdoc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	SKReaderLength = 32
	SKReaderInfo   = "SKReader"

	SKDeviceLength = 32
	SKDeviceInfo   = "SKDevice"
)

var ReaderIdentifier = []byte{0, 0, 0, 0, 0, 0, 0, 0}
var DeviceIdentifier = []byte{0, 0, 0, 0, 0, 0, 0, 1}

func GenerateESessionPrivateKey(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	if curve == nil {
		curve = ecdh.P256()
	}
	return curve.GenerateKey(rand.Reader)
}

func SKReader(
	ePrivateKey *ecdh.PrivateKey,
	ePublicKey *ecdh.PublicKey,
	sessionTranscriptBytes []byte,
) ([]byte, error) {
	return sk(
		ePrivateKey,
		ePublicKey,
		sessionTranscriptBytes,
		SKReaderInfo,
		SKReaderLength,
	)
}

func SKDevice(
	ePrivateKey *ecdh.PrivateKey,
	ePublicKey *ecdh.PublicKey,
	sessionTranscriptBytes []byte,
) ([]byte, error) {
	return sk(
		ePrivateKey,
		ePublicKey,
		sessionTranscriptBytes,
		SKDeviceInfo,
		SKDeviceLength,
	)
}

func sk(
	privateKey *ecdh.PrivateKey,
	publicKey *ecdh.PublicKey,
	sessionTranscriptBytes []byte,
	info string,
	length int,
) ([]byte, error) {
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	salt := crypto.SHA256.New()
	_, err = salt.Write(sessionTranscriptBytes)
	if err != nil {
		return nil, err
	}

	skSource := hkdf.New(
		crypto.SHA256.New,
		sharedSecret,
		salt.Sum(nil),
		[]byte(info),
	)

	sk := make([]byte, length)
	_, err = io.ReadFull(skSource, sk)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

type SessionEncryption struct {
	encryptionCipher     cipher.AEAD
	encryptionIndetifier []byte
	encryptionCounter    uint32
	decryptionCipher     cipher.AEAD
	decryptionIdentifier []byte
	decryptionCounter    uint32
}

func NewReaderSessionEncryption(
	skReader []byte,
	skDevice []byte,
) (*SessionEncryption, error) {
	return newSessionEncryption(
		skReader,
		ReaderIdentifier,
		skDevice,
		DeviceIdentifier,
	)
}

func NewDeviceSessionEncryption(
	skDevice []byte,
	skReader []byte,
) (*SessionEncryption, error) {
	return newSessionEncryption(
		skDevice,
		DeviceIdentifier,
		skReader,
		ReaderIdentifier,
	)
}

func newSessionEncryption(
	encryptionSK []byte,
	encryptionIdentifier []byte,
	decryptionSK []byte,
	decryptionIdentifier []byte,
) (*SessionEncryption, error) {
	encryptionBlockCipher, err := aes.NewCipher(encryptionSK)
	if err != nil {
		return nil, err
	}
	encryptionCipher, err := cipher.NewGCM(encryptionBlockCipher)
	if err != nil {
		return nil, err
	}

	decryptionBlockCipher, err := aes.NewCipher(decryptionSK)
	if err != nil {
		return nil, err
	}
	decryptionCipher, err := cipher.NewGCM(decryptionBlockCipher)
	if err != nil {
		return nil, err
	}

	return &SessionEncryption{
		encryptionCipher:     encryptionCipher,
		encryptionIndetifier: encryptionIdentifier,
		encryptionCounter:    0,
		decryptionCipher:     decryptionCipher,
		decryptionIdentifier: decryptionIdentifier,
		decryptionCounter:    0,
	}, nil
}

func (se *SessionEncryption) Encrypt(clearText []byte) []byte {
	return se.encryptionCipher.Seal(nil, se.encryptNonce(), clearText, []byte{})
}

func (se *SessionEncryption) Decrypt(cipherText []byte) ([]byte, error) {
	return se.decryptionCipher.Open(nil, se.decryptNonce(), cipherText, []byte{})
}

func (se *SessionEncryption) encryptNonce() []byte {
	se.encryptionCounter += 1
	nonce := make([]byte, 12)
	copy(nonce, se.encryptionIndetifier)
	copy(nonce[8:], countToBytes(se.encryptionCounter))
	return nonce
}

func (se *SessionEncryption) decryptNonce() []byte {
	se.decryptionCounter += 1
	nonce := make([]byte, 12)
	copy(nonce, se.decryptionIdentifier)
	copy(nonce[8:], countToBytes(se.decryptionCounter))
	return nonce
}

func countToBytes(count uint32) []byte {
	return []byte{
		byte(count >> 24),
		byte(count >> 16),
		byte(count >> 8),
		byte(count >> 0),
	}
}
