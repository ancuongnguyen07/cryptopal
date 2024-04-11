package main

import (
	"cryptopal/set1"
	"errors"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("cryptopal [set/challenge]")
		fmt.Println("e.g: cryptopal 14 -> run set 1 challenge 4")
		panic(errors.New("invalid number of args: expected 2"))
	}
	setChallenge := os.Args[1]

	switch setChallenge {
	case "13":
		set1.S1C3RunChallenge()
	case "14":
		set1.S1C4RunChallenge()
	case "15":
		set1.S1C5RunChallenge()
	case "16":
		set1.S1C6RunChallenge()
	case "17":
		set1.S1C7RunChallenge()
	case "18":
		set1.S1C8RunChallenge()
	default:
		panic(errors.New("invalid set challenge number"))
	}

}
