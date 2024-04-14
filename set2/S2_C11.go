package set2

import (
	"bytes"
	crypto_rand "crypto/rand"
	"cryptopal/set1"
	"errors"
	"fmt"
	math_rand "math/rand"
)

// Return the secure psuedorandom bytes.
// n is the number of bytes.
func randomAESKey(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := crypto_rand.Read(randomBytes)
	if err != nil {
		return []byte{}, err
	}
	return randomBytes, nil
}

// Append randomly n bytes before and after the given text.
func appendBytes(text []byte) []byte {
	lenPrefix := 5 + math_rand.Intn(10-5)
	lenSuffix := 5 + math_rand.Intn(10-5)

	prefix := make([]byte, lenPrefix)
	suffix := make([]byte, lenSuffix)

	crypto_rand.Read(prefix)
	crypto_rand.Read(suffix)

	return append(append(prefix, text...), suffix...)
}

func AESEncOracle(plaintext []byte) ([]byte, int, error) {
	key, err := randomAESKey(BlockSize)
	if err != nil {
		return []byte{}, 0, err
	}

	plaintext = appendBytes(plaintext)
	encryptChoice := math_rand.Intn(2)

	var ciphertext []byte
	switch encryptChoice {
	case 0:
		{
			// ECB mode
			ciphertext, err = set1.EncryptAES128ECB(plaintext, key)
			if err != nil {
				return []byte{}, 0, err
			}
		}
	case 1:
		{
			// CBC mode
			IV, err := randomAESKey(BlockSize)
			if err != nil {
				return []byte{}, 0, err
			}
			ciphertext, err = EncryptCBC(plaintext, key, IV)
			if err != nil {
				return []byte{}, 0, err
			}

		}
	default:
		return []byte{}, 0, errors.New("invalid encryption mode choice, only ECB(0) or CBC(1)")
	}
	return ciphertext, encryptChoice, nil
}

// Return TRUE if the given ciphertext was ECB-encrypted.
func ecbDetection(ciphertext []byte, blockSize int) bool {
	for i := 0; i < len(ciphertext); i += blockSize {
		for k := i + blockSize; k < len(ciphertext); k += blockSize {
			endIndex1 := min(i+blockSize, len(ciphertext))
			endIndex2 := min(k+blockSize, len(ciphertext))
			if bytes.Equal(ciphertext[i:endIndex1], ciphertext[k:endIndex2]) {
				return true
			}
		}
	}
	return false
}

func S2C11RunChallenge() error {
	correctGuess := 0
	n := 1000
	plaintext := bytes.Repeat([]byte{'c'}, 16*5)
	for range n {
		ciphertext, encMode, err := AESEncOracle(plaintext)
		if err != nil {
			return err
		}

		var guess int
		if ecbDetection(ciphertext, BlockSize) {
			guess = 0
		} else {
			guess = 1
		}

		if guess == encMode {
			correctGuess++
		}
	}

	fmt.Printf("Correct percentage: %.2f%%\n", float64(correctGuess)/float64(n)*100)
	return nil
}
