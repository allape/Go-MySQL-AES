package mysql_aes

import "testing"

// select hex(aes_encrypt('你好', '123456')) from dual
// 62C8DCB75B426AF6A5C0EB2DE5847795

const password = "123456"
const plain = "你好"
const encrypted = "62C8DCB75B426AF6A5C0EB2DE5847795"

func TestEncryptToHex(t *testing.T) {
	hex, err := EncryptToHex(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	if hex != encrypted {
		t.Fatal("encryption is not identical")
	}
}

func TestDecryptFromHex(t *testing.T) {
	decrypted, err := DecryptFromHex(encrypted, password)
	if err != nil {
		t.Fatal(err)
	}
	if plain != decrypted {
		t.Fatal("decryption is not identical")
	}
}
