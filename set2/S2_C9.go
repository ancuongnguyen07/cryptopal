package set2

import (
	"bytes"
	"fmt"
)

func PKCS7Padding(s []byte, blockSize int) []byte {
	leftOverBytes := len(s) % blockSize
	if leftOverBytes > 0 {
		paddedBytes := blockSize - leftOverBytes
		return append(s, bytes.Repeat([]byte{byte(paddedBytes)}, paddedBytes)...)
	}
	return s
}

// Remove the trail of padding bytes.
// Assume the given text was already padded.
func PKCS7Strip(text []byte) []byte {
	if len(text) == 0 {
		return []byte{}
	}

	paddedByte := text[len(text)-1]
	return text[:len(text)-int(paddedByte)]
}

func S2C9RunChallenge() error {
	text := "YELLOW SUBMARINE"
	blockSize := 20
	paddedText := PKCS7Padding([]byte(text), blockSize)

	fmt.Println("Text:", text)
	fmt.Println("Bytes of text:", []byte(text))
	fmt.Println("Padded bytes of text:", paddedText)
	fmt.Println("Block size:", blockSize)
	return nil
}
