package main

import (
	"cryptopal/set1"
	"cryptopal/set2"
	"errors"
	"fmt"
	"os"
)

func runChallenge(setChallenge string) error {
	var challengeFunc func() error
	switch setChallenge {
	case "13":
		challengeFunc = set1.S1C3RunChallenge
	case "14":
		challengeFunc = set1.S1C4RunChallenge
	case "15":
		challengeFunc = set1.S1C5RunChallenge
	case "16":
		challengeFunc = set1.S1C6RunChallenge
	case "17":
		challengeFunc = set1.S1C7RunChallenge
	case "18":
		challengeFunc = set1.S1C8RunChallenge
	case "29":
		challengeFunc = set2.S2C9RunChallenge
	case "210":
		challengeFunc = set2.S2C10RunChallenge
	case "211":
		challengeFunc = set2.S2C11RunChallenge
	case "212":
		challengeFunc = set2.S2C12RunChallenge
	case "213":
		challengeFunc = set2.S2C13RunChallenge
	case "214":
		challengeFunc = set2.S2C14RunChallenge
	case "215":
		challengeFunc = set2.S2C15RunChallenge
	case "216":
		challengeFunc = set2.S2C16RunChallenge
	default:
		return errors.New("invalid set challenge number")
	}

	return challengeFunc()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("cryptopal [set/challenge]")
		fmt.Println("e.g: cryptopal 14 -> run set 1 challenge 4")
		fmt.Printf("invalid number of args: expected 2, got %d\n", len(os.Args))
		os.Exit(1)
	}
	setChallenge := os.Args[1]

	err := runChallenge(setChallenge)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
