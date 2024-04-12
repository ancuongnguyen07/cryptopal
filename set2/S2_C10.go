package set2

import (
	"bytes"
	"crypto/aes"
	"cryptopal/utils"
	"encoding/base64"
	"fmt"
	"os"
)

const BlockSize = 16 // num of bytes = 128 bits

func EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	paddedPlaintext := PKCS7Padding(plaintext, BlockSize)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	toBeXOR := iv
	ciphertext := make([]byte, len(paddedPlaintext))
	for i := 0; i < len(paddedPlaintext); i += BlockSize {
		endIndex := i + BlockSize
		plainBlock := paddedPlaintext[i:endIndex]

		// Do XORwith the IV or the previous output of block cipher
		plainBlock, err = utils.XOR(plainBlock, toBeXOR)
		if err != nil {
			return []byte{}, err
		}

		// Do ECB encryption on each block
		cipher.Encrypt(ciphertext[i:endIndex], plainBlock)
		// update to be XORed
		toBeXOR = ciphertext[i:endIndex]

	}
	return ciphertext, nil
}

func DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	paddedCiphertext := PKCS7Padding(ciphertext, BlockSize)

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	toBeXOR := iv
	plaintext := make([]byte, len(paddedCiphertext))
	for i := 0; i < len(paddedCiphertext); i += BlockSize {
		endIndex := i + BlockSize
		cipherBlock := paddedCiphertext[i:endIndex]

		// Do ECB decryption on each block
		cipher.Decrypt(plaintext[i:endIndex], cipherBlock)
		plainBlock := plaintext[i:endIndex]

		plainBlock, err = utils.XOR(plainBlock, toBeXOR)
		if err != nil {
			return []byte{}, err
		}

		copy(plaintext[i:endIndex], plainBlock)
		// update to be XORed
		toBeXOR = cipherBlock
	}
	return plaintext[:len(ciphertext)], nil
}

func S2C10RunChallenge() error {
	key := "YELLOW SUBMARINE"
	iv := bytes.Repeat([]byte{0}, BlockSize)

	base64Data, err := os.ReadFile("set2/10.txt")
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return err
	}

	paddedPlaintext, err := DecryptCBC(data, []byte(key), iv)
	if err != nil {
		return err
	}
	fmt.Println(string(PKCS7Strip(paddedPlaintext)))
	return nil
}
