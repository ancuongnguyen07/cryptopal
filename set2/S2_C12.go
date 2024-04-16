package set2

import (
	"bytes"
	"cryptopal/set1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

var GlobalKey []byte

func init() {
	key, err := RandomKey(16)
	if err != nil {
		panic(err)
	}
	GlobalKey = key
}

func oracleEncrypt(plaintext []byte) ([]byte, error) {
	key := GlobalKey
	unknownStr, err := os.ReadFile("set2/12.txt")
	if err != nil {
		return []byte{}, err
	}
	unknownStr, err = base64.StdEncoding.DecodeString(string(unknownStr))
	if err != nil {
		return []byte{}, err
	}

	plaintext = append(plaintext, unknownStr...)
	ciphertext, err := set1.EncryptAES128ECB(plaintext, key)
	if err != nil {
		return []byte{}, err
	}

	return ciphertext, nil
}

func detectECBBlockSize() (int, error) {

	feedPtx := []byte{'a'}
	ciphertext, err := oracleEncrypt(feedPtx)
	if err != nil {
		return 0, err
	}

	for i := 0; ; i++ {
		feedPtx = append(feedPtx, byte('a'))
		ctx, err := oracleEncrypt(feedPtx)
		if err != nil {
			return 0, err
		}
		if len(ctx) != len(ciphertext) {
			return len(ctx) - len(ciphertext), nil
		}
	}
}

// Byte-at-a-time ECB decryption breaking.
// Assume that the oracle encryption appends the secret string
// to every given plaintext.
//
// # ciphertext = AES-128-ECB(your string || secret string, key)
func breakingECB(blockSize int) ([]byte, error) {
	ctx, err := oracleEncrypt([]byte{})
	if err != nil {
		return []byte{}, err
	}

	// a potential length of the secret string
	secretLen := len(ctx)
	trueSecretLen := 0
	secretStr := make([]byte, secretLen)

	ciphertextList := make([][]byte, blockSize)

	for i := 0; i < secretLen; i++ {
		// i here is also the number of known bytes in the secret string

		targetBlockIndex := i / blockSize
		numOfPads := blockSize - 1 - (i % blockSize)

		// Feeding the custommized plaintext here to make the oracle
		// return the encrypted byte of secret message which is at the last
		// byte of the cipher block.
		feedPtx := bytes.Repeat([]byte{'c'}, numOfPads)
		if targetBlockIndex == 0 {
			ctx, err = oracleEncrypt(feedPtx)
			if err != nil {
				return []byte{}, err
			}
			ciphertextList[i] = ctx

		} else {
			ctx = ciphertextList[i%blockSize]
		}

		for c := 0; c < 256; c++ {
			// do brute-force for the last byte of target block
			startIndex := targetBlockIndex * blockSize
			refCipherBlock := ctx[startIndex : startIndex+blockSize]

			// This guessed feeding plaintext is used to brute-force the
			// next byte of the secret message
			var guessFeed []byte
			if targetBlockIndex == 0 {
				guessFeed = feedPtx
				guessFeed = append(guessFeed, secretStr[:i]...)
			} else {
				guessFeed = secretStr[i-blockSize+1 : i]
			}
			guessFeed = append(guessFeed, byte(c))

			ciphertext, err := oracleEncrypt(guessFeed)
			if err != nil {
				return []byte{}, err
			}
			if bytes.Equal(refCipherBlock, ciphertext[:blockSize]) {
				secretStr[i] = byte(c)
				trueSecretLen = i
				break
			}
		}

	}

	return secretStr[:trueSecretLen], nil
}

func S2C12RunChallenge() error {

	blockSize, err := detectECBBlockSize()
	if err != nil {
		return err
	}

	// this plaintext is only served for detecting ECB mode
	myStr := bytes.Repeat([]byte{'a'}, blockSize*2)

	if !ecbDetection(myStr, blockSize) {
		return errors.New("ECB mode couldn't be detected")
	}

	secretMsg, err := breakingECB(blockSize)
	if err != nil {
		return err
	}

	fmt.Printf("Secret Message:\n%s\n", string(secretMsg))

	return nil
}
