package set1

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
)

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

func S1C7RunChallenge() {
	data, err := os.ReadFile("set1/7.txt")
	if err != nil {
		panic(err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}

	key := "YELLOW SUBMARINE"
	plaintext, err := DecryptAES128ECB(ciphertext, []byte(key))
	if err != nil {
		panic(err)
	}

	fmt.Println("Plaintext: \n", string(plaintext))
}
