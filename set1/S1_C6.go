package set1

import "math/bits"

// Compute Hamming Distance of two strings.
// Basically it is the number of differing bits between
// the two given strings (arrays of bytes).
func HammingDistance(s1, s2 string) int {
	if len(s1) != len(s2) {
		panic("invalid string length, they should be equal")
	}

	strLen := len(s1)
	count := 0
	diffBytes := make([]byte, strLen)
	for i := 0; i < strLen; i++ {
		diffBytes[i] = s1[i] ^ s2[i]
		count += bits.OnesCount(uint(diffBytes[i]))
	}

	return count
}
