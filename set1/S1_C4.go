package set1

import (
	"bufio"
	"fmt"
	"os"
	"unicode"
)

const cipherFile = "ciphertexts_C4.txt"

// Check if the given string only containing ASCII characters
func IsASCIIRange(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// Set1 | Challenge 4
func S1C4RunChallenge() {
	file, err := os.Open(cipherFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexCiphertext := scanner.Text()

		plaintext, key, err := XORCipher(hexCiphertext)
		if err != nil {
			panic(err)
		}

		if IsASCIIRange(plaintext) && IsASCIIRange(key) {
			fmt.Println("====================================================")
			fmt.Printf("Hex-encoded Ciphertext: %s\n", hexCiphertext)
			fmt.Printf("Key: %s\n", key)
			fmt.Printf("Plaintext: %s\n", plaintext)
		}
	}

}
