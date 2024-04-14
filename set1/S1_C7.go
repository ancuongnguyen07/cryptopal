package set1

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
)

func EncryptAES128ECB(plaintext, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(ciphertext)-16; i += 16 {
		cipher.Encrypt(ciphertext[i:i+16], plaintext[i:i+16])
	}
	return ciphertext, nil
}

func DecryptAES128ECB(ciphertext, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += 16 {
		cipher.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
	}
	return plaintext, nil
}

func S1C7RunChallenge() error {
	data, err := os.ReadFile("set1/7.txt")
	if err != nil {
		return err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	key := "YELLOW SUBMARINE"
	plaintext, err := DecryptAES128ECB(ciphertext, []byte(key))
	if err != nil {
		return err
	}

	fmt.Println("Plaintext: \n", string(plaintext))
	return nil
}
