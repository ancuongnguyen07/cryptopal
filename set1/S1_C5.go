package set1

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Do XOR repeatedly to encrypt/decrypt a message witht the given key.
//
// For example, the given key is "ICE"
// In repeating-key XOR, you'll sequentially apply each byte of the key;
// the first byte of plaintext will be XOR'd against I, the next C, the
// next E, then I again for the 4th byte, and so on.
func RepeatXOR(text string, key string) (string, error) {
	keyLength := len(key)
	if keyLength == 0 {
		return "", errors.New("key length should be greater than 0")
	}

	output := make([]byte, len(text))

	for i := 0; i < len(text); i++ {
		output[i] = text[i] ^ key[i%keyLength]
	}

	return string(output), nil
}

func S1C5RunChallenge() error {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"

	ciphertext, err := RepeatXOR(plaintext, key)
	if err != nil {
		panic(err)
	}
	ciphertext = hex.EncodeToString([]byte(ciphertext))

	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Encrypted text == Expected output: ", expected == ciphertext)
	return nil
}
