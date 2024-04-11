package set1

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/bits"
	"os"
	"strings"
)

// Compute Hamming Distance of two strings.
// Basically it is the number of differing bits between
// the two given strings (arrays of bytes).
func HammingDistance(s1, s2 []byte) int {
	if len(s1) != len(s2) {
		panic("invalid string length, they should be equal")
	}

	strLen := len(s1)
	count := 0
	diffBytes := make([]byte, strLen)
	for i := 0; i < strLen; i++ {
		diffBytes[i] = s1[i] ^ s2[i]
		count += bits.OnesCount(uint(diffBytes[i]))
	}

	return count
}

func sumHammingDistance(s []byte, keySize int) float64 {
	sum := 0.0
	for i := 0; i < len(s)-2*keySize; i += 2 * keySize {
		sum += float64(HammingDistance(s[i:i+keySize], s[i+keySize:i+2*keySize])) / float64(keySize) // normalized
	}

	return sum / (float64(len(s)) / float64(2*keySize)) // take the average
}

func findKeySize(ciphertext []byte) int {
	bestKeySize := 0
	smallestHammingDist := math.MaxFloat64
	for keySize := 2; keySize <= 40; keySize++ {
		// step 3: compute the hamming distance and normalize the result
		hammingDist := sumHammingDistance(ciphertext, keySize)

		if hammingDist < smallestHammingDist {
			smallestHammingDist = hammingDist
			bestKeySize = keySize
		}
	}

	return bestKeySize
}

func S1C6RunChallenge() error {
	data, err := os.ReadFile("set1/6.txt")
	if err != nil {
		return err
	}

	// As the ciphertext has been base64'd after being encrypted
	// We need to de-base64 it.
	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	realKeySize := findKeySize(ciphertext)

	// We need split the ciphertext into `realKeySize` blocks
	// Transpose the blocks of ciphertext. Make a new block that is the first byte of every block.
	// a block that is the second byte of every block, and so on.
	numOfBlocks := len(ciphertext) / realKeySize
	transposedCiphertext := make([][]byte, realKeySize)
	for k_block := 0; k_block < len(transposedCiphertext); k_block++ {
		transposedCiphertext[k_block] = make([]byte, numOfBlocks)
	}

	for i_byte := 0; i_byte < len(transposedCiphertext); i_byte++ {
		for k_block := 0; k_block < numOfBlocks; k_block++ {
			transposedCiphertext[i_byte][k_block] = ciphertext[k_block*realKeySize+i_byte]
		}
	}

	// Solve each block as if it was single-character XOR
	var keyStrBuilder strings.Builder
	for k_block := 0; k_block < len(transposedCiphertext); k_block++ {
		_, block_key, err := XORCipher(string(transposedCiphertext[k_block]))
		if err != nil {
			panic(err)
		}
		keyStrBuilder.WriteString(block_key)
	}

	plaintext, err := RepeatXOR(string(ciphertext), keyStrBuilder.String())
	if err != nil {
		panic(err)
	}

	fmt.Println("Plaintext:\n", plaintext)
	fmt.Println("Key:\n", keyStrBuilder.String())
	fmt.Println("KeySize:\n", realKeySize)

	return nil
}
