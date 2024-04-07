package set1_test

import (
	"cryptopal/set1"
	"testing"
)

func TestHammingDist(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	expected := 37

	hDist := set1.HammingDistance(s1, s2)
	if hDist != expected {
		t.Fatalf("invalid Hamming distance: expected %d, got %d", expected, hDist)
	}
}
