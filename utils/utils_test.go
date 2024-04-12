package utils_test

import (
	"cryptopal/utils"
	"encoding/hex"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	hexString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expectedBase64Str := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	base64Str, err := utils.HexToBase64(hexString)
	if err != nil {
		t.Fatalf(`Error: %v`, err)
	}

	if expectedBase64Str != base64Str {
		t.Fatalf(`Error in converting: expected "%s", got "%s"`, expectedBase64Str, base64Str)
	}
}

func TestXOR(t *testing.T) {
	str1 := "1c0111001f010100061a024b53535009181c"
	str2 := "686974207468652062756c6c277320657965"
	expectedOutput := "746865206b696420646f6e277420706c6179"

	buff1, err := hex.DecodeString(str1)
	if err != nil {
		t.Fatal(err)
	}

	buff2, err := hex.DecodeString(str2)
	if err != nil {
		t.Fatal(err)
	}

	xoredBuff, err := utils.XOR(buff1, buff2)
	if err != nil {
		t.Fatalf(`There should not be an error: %v`, err)
	}

	if expectedOutput != hex.EncodeToString(xoredBuff) {
		t.Fatalf(`Error in XORing: expected "%s", got "%s"`, expectedOutput, xoredBuff)
	}
}
