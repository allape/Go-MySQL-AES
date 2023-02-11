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

func NewPassword(password string, length int) []byte {
	iv := FillZero(length)
	for index, v := range []byte(password) {
		iv[index%length] ^= v
	}
	return iv
}

func NewBlock(passwordStr string) (cipher.Block, error) {
	password := NewPassword(passwordStr, aes.BlockSize)
	return aes.NewCipher(password)
}

func Encrypt(password string, plain []byte) (HexString, error) {
	block, err := NewBlock(password)
	if err != nil {
		return "", err
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

	return strings.ToUpper(hex.EncodeToString(res)), nil
}

func Decrypt(password string, data []byte) ([]byte, error) {
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

// TODO test, reader, writer
