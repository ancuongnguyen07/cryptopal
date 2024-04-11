package set1

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
)

func isECBEncrypted(ciphertext []byte) (bool, error) {
	blockSize := 16

	for i := 0; i < len(ciphertext); i += blockSize {
		endIndex := min(i+blockSize, len(ciphertext))
		firstCipherBlock := ciphertext[i:endIndex]
		for k := i + blockSize; k < len(ciphertext); k += blockSize {
			endIndex := min(k+blockSize, len(ciphertext))
			secondCipherBlock := ciphertext[k:endIndex]
			if bytes.Equal(firstCipherBlock, secondCipherBlock) {
				return true, nil
			}
		}
	}

	return false, nil

}

func S1C8RunChallenge() error {
	file, err := os.Open("set1/8.txt")
	if err != nil {
		return err
	}
	defer file.Close()

	ECBEncrypted := []int{}
	var inputData [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexCiphertext := scanner.Bytes()

		ciphertext := make([]byte, hex.DecodedLen(len(hexCiphertext)))
		n, err := hex.Decode(ciphertext, hexCiphertext)
		if err != nil {
			return err
		}
		ciphertext = ciphertext[:n]

		inputData = append(inputData, ciphertext)
	}

	for i, line := range inputData {
		isECBEncryptedC, err := isECBEncrypted(line)
		if err != nil {
			return err
		}
		if isECBEncryptedC {
			ECBEncrypted = append(ECBEncrypted, i)
		}
	}

	fmt.Println("Hex-encoded ciphertext that was ECB-encrypted (line number):\n", ECBEncrypted)
	return nil
}
