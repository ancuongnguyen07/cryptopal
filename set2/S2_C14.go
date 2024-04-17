package set2

import (
	"bytes"
	"cryptopal/set1"
	"fmt"
	"math/rand"
)

func oraclePrefixEncrypt(plaintext []byte) ([]byte, error) {
	key := GlobalKey
	unknownStr := hiddenMess

	prefixLen := 1 + rand.Intn(BlockSize)
	randomPrefix, err := RandomBytes(prefixLen)
	if err != nil {
		return []byte{}, err
	}

	plaintext = append(randomPrefix, plaintext...)
	plaintext = append(plaintext, unknownStr...)

	ciphertext, err := set1.EncryptAES128ECB(plaintext, key)
	if err != nil {
		return []byte{}, err
	}

	return ciphertext, nil
}

// checkRandomPrefixLen returns if the lenght of random prefix
// is divisible by blocksize. Assume that the encrypted plaintext
// has at least two identical blocks.
func checkRandomPrefixLen(ciphertext []byte, blockSize int) bool {
	for i := 0; i < len(ciphertext)-blockSize; i += blockSize {
		if bytes.Equal(ciphertext[i:i+blockSize], ciphertext[i+blockSize:i+2*blockSize]) {
			return true
		}
	}
	return false
}

// getStructuredCtx returns the ciphertext which is removed of the random prefix
// and the two identical blocks, resulting in the (attacker-controlled || target-bytes)
// ciphertext.
func getStructuredCtx(feedPtx []byte, blockSize int) ([]byte, error) {
	for {
		ctx, err := oraclePrefixEncrypt(feedPtx)
		if err != nil {
			return []byte{}, err
		}
		if checkRandomPrefixLen(ctx, blockSize) {
			// if the random prefix is divisible by the blocksize
			// remove that block of prefix and the two identical blocks
			// added by the attacker.
			return ctx[blockSize*3:], nil
		}
	}
}

func breakingECBRandomPrefix(blockSize int) ([]byte, error) {
	twoIdenticalBlocks := bytes.Repeat([]byte{1}, blockSize*2)
	ctx, err := getStructuredCtx(twoIdenticalBlocks, blockSize)
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
		feedPtx = append(twoIdenticalBlocks, feedPtx...)

		var feedCtx []byte
		if targetBlockIndex == 0 {
			feedCtx, err = getStructuredCtx(feedPtx, blockSize)
			if err != nil {
				return []byte{}, err
			}
			ciphertextList[i] = feedCtx

		} else {
			feedCtx = ciphertextList[i%blockSize]
		}

		// do brute-force for the last byte of target block
		startIndex := targetBlockIndex * blockSize
		refCipherBlock := feedCtx[startIndex : startIndex+blockSize]
		for c := 0; c < 256; c++ {

			// This guessed feeding plaintext is used to brute-force the
			// next byte of the secret message
			var guessFeed []byte
			if targetBlockIndex == 0 {
				guessFeed = feedPtx
				guessFeed = append(guessFeed, secretStr[:i]...)
			} else {
				guessFeed = twoIdenticalBlocks
				guessFeed = append(guessFeed, secretStr[i-blockSize+1:i]...)
			}
			guessFeed = append(guessFeed, byte(c))

			ciphertext, err := getStructuredCtx(guessFeed, blockSize)
			if err != nil {
				return []byte{}, err
			}

			// fmt.Println(refCipherBlock)
			// fmt.Println(ciphertext[:blockSize])
			// fmt.Println("------------------------------------")

			if bytes.Equal(refCipherBlock, ciphertext[:blockSize]) {
				// fmt.Println("Secret byte found")
				secretStr[i] = byte(c)
				trueSecretLen = i
				break
			}
		}

	}
	return secretStr[:trueSecretLen], nil
}

func S2C14RunChallenge() error {
	blockSize, err := detectECBBlockSize()
	if err != nil {
		return err
	}

	secretMsg, err := breakingECBRandomPrefix(blockSize)
	if err != nil {
		return err
	}

	fmt.Printf("Secret Message:\n%s\n", string(secretMsg))

	return nil
}
