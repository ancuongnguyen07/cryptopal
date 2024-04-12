package set2_test

import (
	"bytes"
	"cryptopal/set2"
	"testing"
)

func TestCipherCBC(t *testing.T) {
	plaintext := "CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages"
	key := "YELLOW SUBMARINE"
	iv := bytes.Repeat([]byte{0}, set2.BlockSize)

	ciphertext, err := set2.EncryptCBC([]byte(plaintext), []byte(key), iv)
	if err != nil {
		t.Fatal(err)
	}
	decryptedCiphertext, err := set2.DecryptCBC(ciphertext, []byte(key), iv)
	if err != nil {
		t.Fatal(err)
	}
	removedPaddingText := set2.PKCS7Strip(decryptedCiphertext)
	if !bytes.Equal(removedPaddingText, []byte(plaintext)) {
		t.Fatal("invalid encrypted text, it should be equal the plaintext")
	}

}
