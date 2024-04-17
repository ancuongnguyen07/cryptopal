package set2

import (
	"fmt"
)

// PKCS7Validation determines if the given plaintext has
// valid PKCS#7 padding, then return the stripped-off version.
func PKCS7ValidateAndStrip(plaintext []byte) ([]byte, bool) {
	n := len(plaintext)
	numOfPads := int(plaintext[n-1])
	if int(plaintext[n-numOfPads]) != numOfPads {
		return []byte{}, false
	}

	return plaintext[:n-numOfPads], true
}

func S2C15RunChallenge() error {
	paddedPlaintexts := []string{
		"ICE ICE BABY\x04\x04\x04\x04",
		"ICE ICE BABY\x05\x05\x05\x05",
		"ICE ICE BABY\x01\x02\x03\x04",
	}

	for _, paddedPtx := range paddedPlaintexts {
		strippedPlaintext, isValid := PKCS7ValidateAndStrip([]byte(paddedPtx))

		fmt.Println("Padded plaintext:\n", []byte(paddedPtx))
		if isValid {
			fmt.Println("---> Valid PKCS#7 padding")
			fmt.Println("Stripped-off plaintext:\n", strippedPlaintext)
		} else {
			fmt.Println("---> Invalid PKCS#7 padding")
		}
		fmt.Println("==============================================")

	}

	return nil
}
