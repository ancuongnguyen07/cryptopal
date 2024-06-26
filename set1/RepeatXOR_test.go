package set1_test

import (
	"cryptopal/set1"
	"encoding/hex"
	"testing"
)

func TestRepeatXOR(t *testing.T) {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	ciphertext, err := set1.RepeatXOR(plaintext, key)
	if err != nil {
		panic(err)
	}
	ciphertext = hex.EncodeToString([]byte(ciphertext))

	if expected != ciphertext {
		t.Fatalf("invalid output: expected %s, got %s", expected, ciphertext)
	}
}
