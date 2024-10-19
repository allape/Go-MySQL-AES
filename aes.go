package mysql_aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
)

type HexString = string

func FillZero(length int) []byte {
	return bytes.Repeat([]byte{0}, length)
}

func NewPassword(password []byte, length int) []byte {
	iv := FillZero(length)
	for index, v := range password {
		iv[index%length] ^= v
	}
	return iv
}

func NewBlock(password []byte) (cipher.Block, error) {
	return aes.NewCipher(NewPassword(password, aes.BlockSize))
}

func Encrypt(plain, password []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}

	block, err := NewBlock(password)
	if err != nil {
		return nil, err
	}
	paddingCount := len(plain) % block.BlockSize()
	paddingCount = block.BlockSize() - paddingCount
	plain = append(plain, bytes.Repeat([]byte{byte(paddingCount)}, paddingCount)...)

	totalLength := len(plain)

	res := make([]byte, totalLength, totalLength)
	for i := 0; i < totalLength/block.BlockSize(); i++ {
		startIndex := i * block.BlockSize()
		endIndex := startIndex + block.BlockSize()
		block.Encrypt(res[startIndex:endIndex], plain[startIndex:endIndex])
	}

	return res, nil
}

func Decrypt(data, password []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	block, err := NewBlock(password)
	if err != nil {
		return nil, err
	}

	totalLength := len(data)

	res := make([]byte, totalLength, totalLength)
	for i := 0; i < totalLength/block.BlockSize(); i++ {
		startIndex := i * block.BlockSize()
		endIndex := startIndex + block.BlockSize()
		block.Decrypt(res[startIndex:endIndex], data[startIndex:endIndex])
	}

	paddingSize := res[len(res)-1]
	res = res[0 : len(res)-int(paddingSize)]

	return res, nil
}

func EncryptToHex(plain, password string) (HexString, error) {
	if plain == "" {
		return "", nil
	}
	encrypted, err := Encrypt([]byte(plain), []byte(password))
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(encrypted)), nil
}

func DecryptFromHex(encryptedHex, password string) (HexString, error) {
	if encryptedHex == "" {
		return "", nil
	}
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}
	plain, err := Decrypt(encrypted, []byte(password))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
