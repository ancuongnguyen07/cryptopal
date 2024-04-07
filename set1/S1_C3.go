// Set1 | Challenge 3.

package set1

import (
	"encoding/hex"
	"fmt"
)

// Return a count/frequency map to each characters in the given string
func GetCount(text string) map[rune]int {
	count := make(map[rune]int)
	for _, c := range text {
		_, ok := count[c]
		if !ok {
			count[c] = 0
		}
		count[c]++
	}

	return count
}

// Return the value which has the greatest count
func GetMaxCount(freqMap map[rune]int) rune {
	maxCount, maxChar := 0, 0
	for letter, count := range freqMap {
		if count > maxCount {
			maxChar = int(letter)
			maxCount = count
		}
	}

	return rune(maxChar)
}

// Decrypt a ciphertext by XORing it with the given key
func Xor(ciphertext []byte, key byte) string {
	decryptedText := make([]byte, len(ciphertext))
	for i, c := range ciphertext {
		decryptedText[i] = c ^ key
	}

	return string(decryptedText)
}

// The given hex-encoded ciphertext has been XORed against a single character.
// Find the key, decrypt the message.
//
// Return:
//
// - plaintext
//
// - key
//
// - err
func XORCipher(hexCiphertext string) (string, string, error) {
	ciphertext, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return "", "", err
	}
	freqMap := GetCount(string(ciphertext))
	key := GetMaxCount(freqMap) ^ 32 // uppecase and space

	plaintext := Xor(ciphertext, byte(key))

	return plaintext, string(key), nil
}

func S1C3RunChallenge() {
	// hex-encoded ciphertext
	hexCiphertext := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	plaintext, key, err := XORCipher(hexCiphertext)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Hex-encoded Ciphertext: %s\n", hexCiphertext)
	fmt.Printf("Key:%s\nPlaintext: %s\n", key, plaintext)
}
