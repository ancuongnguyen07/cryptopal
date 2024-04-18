package set2

import (
	"fmt"
	"strings"
)

const prefix = "comment1=cooking%20MCs;userdata="
const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

// escapeSpecialChars escape out the ';' and '=' characters.
func escapeSpecialChars(input string) string {
	var sb strings.Builder
	for _, char := range input {
		if char == ';' {
			// binary of ';' is 0b111011 (59)
			// binary of '?' is 0b111111 (63)
			// As I chose the '?' will replace ';', their distance
			// in ASCII code is 4 --> Needs to flip the 3rd bit
			// In the attack: we want to convert '?' to ';'
			// Look at the 3rd bit: 1 ---> 0
			sb.WriteString("?")
		} else if char == '=' {
			// binary of '=' is 0b111101 (61)
			// binary of '9' is 0b111001 (57)
			// As I chose the '9' will replace '=', their distance
			// in ASCII code is 4 --> Needs to flip the 3rd bit
			// In the attack: we want to convert '9' to '='
			// Look at the 3rd bit: 0 ---> 1
			sb.WriteString("9")
		} else {
			sb.WriteRune(char)
		}
	}
	return sb.String()
}

func oracleCBCEncrypt(plaintext, iv []byte) ([]byte, error) {
	ptx := []byte(escapeSpecialChars(string(plaintext)))
	ptx = append([]byte(prefix), ptx...)
	ptx = append(ptx, []byte(suffix)...)

	key := GlobalKey

	ciphertext, err := EncryptCBC(ptx, key, iv)
	if err != nil {
		return []byte{}, err
	}

	return ciphertext, nil
}

// findAdminField returns True if the given encrypted text contains
// ';admin=true'. The given text will be decrypted first then done
// look up.
func findAdminField(ciphertext, iv []byte) (bool, error) {
	key := GlobalKey
	plaintext, err := DecryptCBC(ciphertext, key, iv)
	if err != nil {
		return false, err
	}
	fmt.Println(string(plaintext))

	return strings.Contains(string(plaintext), ";admin=true;"), nil
}

func bitflippingAttack(ciphertext, iv []byte) ([]byte, error) {
	// The cipher block of our customized input is on the 3rd.
	// We need to bitflipping on the 2nd block to affect the
	// 3rd block.
	targetBlock := ciphertext[BlockSize : BlockSize*2]
	// In my input, 5th byte is the ';'
	targetBlock[5] ^= 4
	// In my input, 11th byte is the '='
	targetBlock[11] ^= 4

	doesIncludeAdmin, err := findAdminField(ciphertext, iv)
	if err != nil {
		return []byte{}, err
	}

	if doesIncludeAdmin {
		return ciphertext, nil
	}

	return []byte{}, nil
}

func S2C16RunChallenge() error {
	iv, err := RandomBytes(BlockSize)
	if err != nil {
		return err
	}

	input := "00000;admin=true"
	ciphertext, err := oracleCBCEncrypt([]byte(input), iv)
	if err != nil {
		return err
	}

	// attacker modified the ciphertext here
	cipherAttack, err := bitflippingAttack(ciphertext, iv)
	if err != nil {
		return err
	}
	fmt.Println("Cipher attack:\n", string(cipherAttack))

	doesIncludeAdmin, err := findAdminField(ciphertext, iv)
	if err != nil {
		return err
	}
	fmt.Printf("Is '%s' included? %t\n", "admin", doesIncludeAdmin)

	return nil
}
