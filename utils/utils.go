package utils

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Convert a hex string into base64 format
func HexToBase64(hexString string) (string, error) {
	// Decode hex data
	data, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	// Encode data to base64
	base64Data := base64.StdEncoding.EncodeToString(data)
	return string(base64Data), nil
}

// Do XOR on two equal-length buffers
func XOR(str1, str2 string) (string, error) {
	buf1, err := hex.DecodeString(str1)
	if err != nil {
		return "", err
	}
	buf2, err := hex.DecodeString(str2)
	if err != nil {
		return "", err
	}

	if len(buf1) != len(buf2) {
		return "", errors.New("invalid lenghts, they should be equal")
	}

	xoredBuff := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i++ {
		xoredBuff[i] = buf1[i] ^ buf2[i]
	}

	return hex.EncodeToString(xoredBuff), nil
}
