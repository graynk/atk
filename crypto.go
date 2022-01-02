package main

import (
	"crypto/aes"
	"crypto/cipher"
	"golang.org/x/crypto/scrypt"
)

func deriveKey(password []byte, slot slot) ([]byte, error) {
	return scrypt.Key(password, slot.Salt, slot.N, slot.R, slot.P, 32)
}

func decryptData(key, data []byte, dataParams params) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	taggedData := append(data, dataParams.Tag...)
	return gcm.Open(nil, dataParams.Nonce, taggedData, nil)
}
