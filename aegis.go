package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

type hexedBytes []byte
type based64Bytes []byte

type aegis struct {
	Version int
	Header  header
	Db      based64Bytes
}

type header struct {
	Slots  []slot
	Params params
}

type slot struct {
	Type   int
	Uuid   string
	Key    hexedBytes
	Params params `json:"key_params"`
	N      int
	R      int
	P      int
	Salt   hexedBytes
}

type params struct {
	Nonce hexedBytes
	Tag   hexedBytes
}

func (a aegis) Decrypt(password []byte) {
	var masterKey []byte
	for _, slot := range a.Header.Slots {
		if slot.Type != 1 {
			continue
		}
		derived, err := deriveKey(password, slot)
		if err != nil {
			continue
		}
		decrypted, err := decryptData(derived, slot.Key, slot.Params)
		if err != nil {
			continue
		}
		masterKey = decrypted
		break
	}

	if masterKey == nil {
		errAndExit("Provided password did not match any of the slots", nil)
	}

	output, err := decryptData(masterKey, a.Db, a.Header.Params)
	if err != nil {
		errAndExit("Failed to decrypt database field: %v", err)
	}

	fmt.Println("Data:\t ", string(output))
}

func (b *hexedBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("empty field")
	}
	data = data[1 : len(data)-1]
	buffer := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(buffer, data)
	if err != nil {
		return err
	}
	*b = buffer[:n]
	return nil
}

func (b *based64Bytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("empty field")
	}
	data = data[1 : len(data)-1]
	data = bytes.ReplaceAll(data, []byte{'\\'}, []byte{})
	buffer := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(buffer, data)
	if err != nil {
		return err
	}
	*b = buffer[:n]
	return nil
}
