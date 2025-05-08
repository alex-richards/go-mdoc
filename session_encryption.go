package mdoc

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	skReaderLength = 32
	skReaderInfo   = "SKReader"

	skDeviceLength = 32
	skDeviceInfo   = "SKDevice"
)

var ReaderIdentifier = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
var DeviceIdentifier = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}

func SKReader(
	agreer Agreer,
	ephemeralKey *PublicKey,
	sessionTranscriptBytes []byte,
) ([]byte, error) {
	return sk(
		agreer,
		ephemeralKey,
		sessionTranscriptBytes,
		skReaderInfo,
		skReaderLength,
	)
}

func SKDevice(
	agreer Agreer,
	ephemeralKey *PublicKey,
	sessionTranscriptBytes []byte,
) ([]byte, error) {
	return sk(
		agreer,
		ephemeralKey,
		sessionTranscriptBytes,
		skDeviceInfo,
		skDeviceLength,
	)
}

func sk(
	agreer Agreer,
	deviceKey *PublicKey,
	sessionTranscriptBytes []byte,
	info string,
	length int,
) ([]byte, error) {
	sharedSecret, err := agreer.Agree(deviceKey)
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
	encryptionIdentifier [8]byte
	encryptionCounter    uint32
	decryptionCipher     cipher.AEAD
	decryptionIdentifier [8]byte
	decryptionCounter    uint32
}

func NewSessionEncryption(
	encryptionSK []byte,
	encryptionIdentifier [8]byte,
	decryptionSK []byte,
	decryptionIdentifier [8]byte,
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
		encryptionIdentifier: encryptionIdentifier,
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
	se.encryptionCounter++
	nonce := make([]byte, 12)
	copy(nonce, se.encryptionIdentifier[:])
	copy(nonce[8:], countToBytes(se.encryptionCounter))
	return nonce
}

func (se *SessionEncryption) decryptNonce() []byte {
	se.decryptionCounter++
	nonce := make([]byte, 12)
	copy(nonce, se.decryptionIdentifier[:])
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
