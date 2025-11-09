package goksef

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type EncryptionData struct {
	CipherKey             []byte
	CipherIV              []byte
	EncryptedCipherKey    string
	EncryptedSymmetricKey string
	InitializationVector  string
}

type FileMetadata struct {
	FileSize int64
	HashSHA  string
}

func GetEncryptionData(symetricKeyEncryptionPEM string) (*EncryptionData, error) {
	publicKey, err := parsePublicKeyFromCertificatePEM(symetricKeyEncryptionPEM)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	key, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate symmetric key: %w", err)
	}

	iv, err := randomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	encryptedKey, err := encryptWithRSAUsingPublicKey(key, publicKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt symmetric key: %w", err)
	}

	encodedEncryptedKey := base64.StdEncoding.EncodeToString(encryptedKey)
	initializationVector := base64.StdEncoding.EncodeToString(iv)

	return &EncryptionData{
		CipherKey:             key,
		CipherIV:              iv,
		EncryptedCipherKey:    encodedEncryptedKey,
		EncryptedSymmetricKey: encodedEncryptedKey,
		InitializationVector:  initializationVector,
	}, nil
}

func GetMetaData(file []byte) (*FileMetadata, error) {
	sum := sha256.Sum256(file)
	base64Hash := base64.StdEncoding.EncodeToString(sum[:])

	return &FileMetadata{
		FileSize: int64(len(file)),
		HashSHA:  base64Hash,
	}, nil
}

func base64PublicKeyToPEM(b64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func EncryptBytesWithAES256(content, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length: got %d, want 32", len(key))
	}
	if len(iv) != aes.BlockSize { // 16
		return nil, fmt.Errorf("invalid IV length: got %d, want %d", len(iv), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded, err := pkcs7Pad(content, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func DecryptBytesWithAES256(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length: got %d, want 32", len(key))
	}
	if len(iv) != aes.BlockSize { // 16
		return nil, fmt.Errorf("invalid IV length: got %d, want %d", len(iv), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

func pkcs7Unpad(src []byte, blockSize int) ([]byte, error) {
	if len(src) == 0 || len(src)%blockSize != 0 {
		return nil, errors.New("invalid padding size")
	}

	padLen := int(src[len(src)-1])
	if padLen == 0 || padLen > len(src) {
		return nil, errors.New("invalid padding")
	}

	for _, v := range src[len(src)-padLen:] {
		if int(v) != padLen {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:len(src)-padLen], nil
}

func pkcs7Pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if src == nil {
		return nil, errors.New("pkcs7Pad: source is nil")
	}
	padLen := blockSize - (len(src) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(src)+padLen)
	copy(out, src)
	for i := len(src); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out, nil
}

func parsePublicKeyFromCertificatePEM(pemStr string) (*rsa.PublicKey, error) {
	var block *pem.Block
	rest := []byte(pemStr)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			pub, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("certificate public key is not RSA")
			}
			return pub, nil

		case "PUBLIC KEY":
			pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKIX public key: %w", err)
			}
			pub, ok := pubAny.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("public key is not RSA")
			}
			return pub, nil

		case "RSA PUBLIC KEY":
			// PKCS#1 RSA public key
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS1 public key: %w", err)
			}
			return pub, nil
		}
	}

	return nil, errors.New("no usable CERTIFICATE or PUBLIC KEY block found")
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func encryptWithRSAUsingPublicKey(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}
