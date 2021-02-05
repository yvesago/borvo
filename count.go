package main

import (
	"fmt"
	"math/big"

	"github.com/gookit/color"
)

type choice struct {
	Alpha *big.Int
	Beta  *big.Int
}

// Count ballots with encrypted results
func Count(elec Election, ballots []Ballot) [][]choice {

	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)

	// Array for new count
	var newCount [][]choice

	// Init array
	for _, q := range elec.Questions {
		var choices []choice
		// start with Blank
		if q.Blank {
			choices = append(choices, choice{Alpha: big.NewInt(1), Beta: big.NewInt(1)})
		}
		for range q.Answers {
			choices = append(choices, choice{Alpha: big.NewInt(1), Beta: big.NewInt(1)})
		}
		newCount = append(newCount, choices)
	}

	// New homomorphic count
	for _, b := range ballots {
		// Ballots homomorphic count
		for ai, a := range b.Answers {
			for ci, c := range a.Choices {
				// Homomorphic Sum
				a1, _ := new(big.Int).SetString(c.Alpha, 10)
				aSum := newCount[ai][ci].Alpha
				aSum = aSum.Mul(aSum, a1).Mod(aSum, prime)
				newCount[ai][ci].Alpha = aSum

				b1, _ := new(big.Int).SetString(c.Beta, 10)
				bSum := newCount[ai][ci].Beta
				bSum = bSum.Mul(bSum, b1).Mod(bSum, prime)
				newCount[ai][ci].Beta = bSum

			}
		}
	}

	return newCount
}

// Decrypt with partial decryption factors
func DecyptResults(elec Election, res Result, newCount [][]choice) (error, [][]int) {

	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)
	g, _ := new(big.Int).SetString(elec.PublicKey.Group.G, 10)

	// [4.18]  Election result
	// Discret log for max num_tallied values
	DL := make(map[string]int)
	dlt := big.NewInt(1)
	for i := 0; i <= res.NumTallied; i++ {
		DL[dlt.String()] = i
		dlt = dlt.Mul(dlt, g).Mod(dlt, prime)
	}

	// Array for new results
	var newResults [][]int

	// Init array
	for _, q := range elec.Questions {
		var choices []int
		// start with Blank
		if q.Blank {
			choices = append(choices, 0)
		}
		for range q.Answers {
			choices = append(choices, 0)
		}
		newResults = append(newResults, choices)
	}

	// Print verified results
	// TODO verifyDecryptionFactors

	for i, _ := range newCount {
		partial := res.PartialDecryptions[0]
		if elec.Questions[i].Blank {
			readAlpha, _ := new(big.Int).SetString(res.EncryptedTally[i][0].Alpha, 10)
			readBeta, _ := new(big.Int).SetString(res.EncryptedTally[i][0].Beta, 10)
			alpha := newCount[i][0].Alpha
			beta := newCount[i][0].Beta
			if alpha.Cmp(readAlpha) != 0 || beta.Cmp(readBeta) != 0 {
				return fmt.Errorf("Read blank Alpha and Beta != Computed Alpha and Beta"), newResults
			}
			// [4.18]  Election result
			// result = logg(beta/f)
			f, _ := new(big.Int).SetString(partial.DecryptionFactors[i][0], 10)
			t := new(big.Int).Mul(beta, new(big.Int).ModInverse(f, prime))
			t = t.Mod(t, prime)
			newResults[i][0] = DL[t.String()]
		}

		a := elec.Questions[i].Answers
		bpos := 0
		if elec.Questions[i].Blank {
			bpos = 1
		}
		for ci, _ := range a {
			readAlpha, _ := new(big.Int).SetString(res.EncryptedTally[i][ci+bpos].Alpha, 10)
			readBeta, _ := new(big.Int).SetString(res.EncryptedTally[i][ci+bpos].Beta, 10)
			alpha := newCount[i][ci+bpos].Alpha
			beta := newCount[i][ci+bpos].Beta
			if alpha.Cmp(readAlpha) != 0 || beta.Cmp(readBeta) != 0 {
				return fmt.Errorf("Read Alpha and Beta != Computed Alpha and Beta"), newResults
			}
			// [4.18]  Election result
			// result = logg(beta/f)
			f, _ := new(big.Int).SetString(partial.DecryptionFactors[i][ci+bpos], 10)
			t := new(big.Int).Mul(beta, new(big.Int).ModInverse(f, prime))
			t = t.Mod(t, prime)
			newResults[i][ci+bpos] = DL[t.String()]
		}
	}

	return nil, newResults // no error
}

// Print decrypted results
func PrintNewResults(elec Election, newResults [][]int) {

	for i, _ := range newResults {
		fmt.Println("*", elec.Questions[i].Question)
		if elec.Questions[i].Max != 1 { // mask common case where min = max = 1
			fmt.Printf("  (min %d, max %d)\n", elec.Questions[i].Min, elec.Questions[i].Max)
		}
		if elec.Questions[i].Blank {
			fmt.Printf("  - Blank : ") // or clear result : res.Result[i][0]
			color.Printf("<suc>%d</>\n", newResults[i][0])
		}

		a := elec.Questions[i].Answers
		bpos := 0
		if elec.Questions[i].Blank {
			bpos = 1
		}
		for ci, _ := range a {
			fmt.Printf("  - %s : ", a[ci]) // clear text result : res.Result[i][ci+bpos]
			color.Printf("<suc>%d</>\n", newResults[i][ci+bpos])
		}
	}

}
