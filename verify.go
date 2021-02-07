package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

func verifyResponseToElection(b Ballot, uuid string, hash string) error {
	// [4.14] fingerprint of election
	//  HJSON(J) = BASE64(SHA256(J))
	// Computed in main function:
	//   selec, _ := json.Marshal(elec)
	//   hashS := sha256.Sum256(selec)
	//   fmt.Println(base64.RawStdEncoding.EncodeToString(hashS[:]))
	if b.ElectionUUID != uuid {
		return fmt.Errorf(" Ballot with Election UUID %s\n  from wrong Election\n", b.ElectionUUID)
	}
	if b.ElectionHash != hash {
		return fmt.Errorf(" Ballot with Election Hash %s\n  from wrong Election\n", b.ElectionHash)
	}
	OK("")
	return nil // no error
}

func verifyBallotSignature(b Ballot, elec Election) error {
	g, _ := new(big.Int).SetString(elec.PublicKey.Group.G, 10)
	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)
	q, _ := new(big.Int).SetString(elec.PublicKey.Group.Q, 10)

	bsPK, _ := new(big.Int).SetString(b.Signature.PublicKey, 10)
	bsr, _ := new(big.Int).SetString(b.Signature.Response, 10)
	bsc, _ := new(big.Int).SetString(b.Signature.Challenge, 10)

	var bCyphers []string
	for _, ai := range b.Answers {
		for _, ci := range ai.Choices {
			bCyphers = append(bCyphers, ci.Alpha)
			bCyphers = append(bCyphers, ci.Beta)
		}
	}

	// [4.13] Signature
	// A = g**response * public_key**challenge (mod p)
	Asa := new(big.Int).Exp(g, bsr, prime)
	Asb := new(big.Int).Exp(bsPK, bsc, prime)
	A := new(big.Int).Mul(Asa, Asb)
	A = A.Mod(A, prime)

	// SHA256(sig|public_key|A|alpha(γ1),beta(γ1),...,alpha(γl),beta(γl)) mod q
	Hsign := fmt.Sprintf("sig|%s|%s|%s", bsPK, A, strings.Join(bCyphers, ","))
	hashS := sha256.Sum256([]byte(Hsign))
	bHashS := new(big.Int).SetBytes(hashS[:])
	left := bHashS.Mod(bHashS, q)

	if left.Cmp(bsc) == 0 {
		OK("")
		return nil // no error
	} else {
		return fmt.Errorf(" Signature ballot with challenge\n  %s\n  KO !!!!!\n", bsc)
	}
}

func verifyBallotBlankProofs(b Ballot, elec Election) error {
	g, _ := new(big.Int).SetString(elec.PublicKey.Group.G, 10)
	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)
	q, _ := new(big.Int).SetString(elec.PublicKey.Group.Q, 10)
	y, _ := new(big.Int).SetString(elec.PublicKey.Y, 10)

	bsPK, _ := new(big.Int).SetString(b.Signature.PublicKey, 10)

	// [4.12] Proofs
	P := fmt.Sprintf("%s,%s,", g, y)

	for i, a := range b.Answers {
		if a.BlankProof == nil { // or elec.Questions[i].Blank == false
			//OK("")
			return nil // no error
		}
		a0, _ := new(big.Int).SetString(a.Choices[0].Alpha, 10)
		b0, _ := new(big.Int).SetString(a.Choices[0].Beta, 10)
		r0, _ := new(big.Int).SetString(a.BlankProof[0].Response, 10)
		c0, _ := new(big.Int).SetString(a.BlankProof[0].Challenge, 10)

		// Homomorphic Sum
		aSum := big.NewInt(1)
		bSum := big.NewInt(1)
		for i, c := range a.Choices {
			if i == 0 {
				continue
			}
			a1, _ := new(big.Int).SetString(c.Alpha, 10)
			aSum = aSum.Mul(aSum, a1).Mod(aSum, prime)
			b1, _ := new(big.Int).SetString(c.Beta, 10)
			bSum = bSum.Mul(bSum, b1).Mod(bSum, prime)
		}

		r1, _ := new(big.Int).SetString(a.BlankProof[1].Response, 10)
		c1, _ := new(big.Int).SetString(a.BlankProof[1].Challenge, 10)

		// [4.12] Proofs
		// P = "g,y,a0,b0,aS,bS"
		P += fmt.Sprintf("%s,%s,%s,%s", a0, b0, aSum, bSum)

		// [4.12.3] Verifyink blank_proof
		// A0 = g**response0 x alpha0**challenge0
		// B0 = y**response0 x beta0**challenge0
		a0a := new(big.Int).Exp(g, r0, prime)
		a0b := new(big.Int).Exp(a0, c0, prime)
		A0 := a0a.Mul(a0a, a0b)
		A0 = A0.Mod(A0, prime)

		b0a := new(big.Int).Exp(y, r0, prime)
		b0b := new(big.Int).Exp(b0, c0, prime)
		B0 := b0a.Mul(b0a, b0b)
		B0 = B0.Mod(B0, prime)

		// A1 = g**response1 x alphaS**challenge1
		// B1 = y**response1 x betaS**challenge1
		a1a := new(big.Int).Exp(g, r1, prime)
		a1b := new(big.Int).Exp(aSum, c1, prime)
		A1 := a1a.Mul(a1a, a1b)
		A1 = A1.Mod(A1, prime)

		b1a := new(big.Int).Exp(y, r1, prime)
		b1b := new(big.Int).Exp(bSum, c1, prime)
		B1 := b1a.Mul(b1a, b1b)
		B1 = B1.Mod(B1, prime)

		// [4.12.1] overall_proof signature
		// "bproof0|public_key|P|A0,B0,A1,B1
		HString := fmt.Sprintf("bproof0|%s|%s|%s,%s,%s,%s", bsPK, P, A0, B0, A1, B1)
		// SUM256("...") mod q
		hashS := sha256.Sum256([]byte(HString))
		bHashS := new(big.Int).SetBytes(hashS[:])
		left := bHashS.Mod(bHashS, q)

		// ( challenge0 +  challenge1 ) mod q
		right := new(big.Int).Mod(c0.Add(c0, c1), q)

		if left.Cmp(right) == 0 {
			OK("")
		} else {
			return fmt.Errorf(" Blank Proof answer %d\n   K0 !!!!!\n", i+1)
		}
	}

	return nil // no error
}

func verifyBallotIndividualProofs(b Ballot, elec Election) error {
	g, _ := new(big.Int).SetString(elec.PublicKey.Group.G, 10)
	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)
	q, _ := new(big.Int).SetString(elec.PublicKey.Group.Q, 10)
	y, _ := new(big.Int).SetString(elec.PublicKey.Y, 10)

	bsPK, _ := new(big.Int).SetString(b.Signature.PublicKey, 10)

	// [4.10.1] individual_proofs for homomorphic answer
	//  iprove(S,r,m,0,1)
	// [4.11]  Proofs of interval membership (0..1)
	//  SUM256("prove|S|α,β|A0,B0,...,Ak,Bk") mos q = total challenges
	for _, a := range b.Answers {
		for ic, c := range a.Choices {
			alpha0, _ := new(big.Int).SetString(c.Alpha, 10) // alpha
			beta0, _ := new(big.Int).SetString(c.Beta, 10)   // beta
			ind := a.IndividualProofs[ic]                    // IndividualProof for alpha and beta

			tc := big.NewInt(0) // total challenges
			M := ""
			for _, m := range []int{0, 1} {
				r0, _ := new(big.Int).SetString(ind[m].Response, 10)
				c0, _ := new(big.Int).SetString(ind[m].Challenge, 10)
				tc = tc.Add(tc, c0).Mod(tc, q)

				// [4.11] proofs of interval
				// A = g**r / alpha**c
				a0a := new(big.Int).Exp(g, r0, prime)       // g**r
				a0Ec := new(big.Int).Exp(alpha0, c0, prime) // alpha**c
				a0b := new(big.Int).ModInverse(a0Ec, prime) // 1/(alpha**c)
				A0 := a0a.Mul(a0a, a0b)
				A0 = A0.Mod(A0, prime)

				// B = y**r / (beta/(g**m)) ** c
				b0a := new(big.Int).Exp(y, r0, prime) // y**r
				mBigInt := big.NewInt(int64(m))
				gEm := new(big.Int).Exp(g, mBigInt, prime)                           // g**m
				b0Dg := new(big.Int).Mul(beta0, new(big.Int).ModInverse(gEm, prime)) // beta/(g**m)
				b0DgEc := new(big.Int).Exp(b0Dg, c0, prime)                          // (beta/(g**m) ** c
				b0b := new(big.Int).ModInverse(b0DgEc, prime)                        // 1/ (beta/(g**m) ** c
				B0 := b0a.Mul(b0a, b0b)
				B0 = B0.Mod(B0, prime)

				M += fmt.Sprintf(",%s,%s", A0, B0)
			}
			// [4.10.1] individual_proofs for homomorphic answer
			// iprove(S,r,m,0,1)
			// [4.11] "prove|S|α,β|A0,B0,...,Ak,Bk"
			HString := fmt.Sprintf("prove|%s|%s,%s|%s", bsPK, alpha0, beta0, M[1:]) // "M[1:]" remove first ","

			// SUM256("...") mod q
			hashS := sha256.Sum256([]byte(HString))
			bHashS := new(big.Int).SetBytes(hashS[:])
			left := bHashS.Mod(bHashS, q)

			// ( challenge0 + challenge1 + challenge ..) mod q
			right := tc

			if left.Cmp(right) == 0 {
				OK("")
			} else {
				return fmt.Errorf(" Overall Proof for ballot with PublicKey\n  %s\n  KO !!!!!\n", bsPK)
			}
		}
	}

	return nil // no error
}

func verifyBallotOverallProofs(b Ballot, elec Election) error {
	g, _ := new(big.Int).SetString(elec.PublicKey.Group.G, 10)
	prime, _ := new(big.Int).SetString(elec.PublicKey.Group.P, 10)
	q, _ := new(big.Int).SetString(elec.PublicKey.Group.Q, 10)
	y, _ := new(big.Int).SetString(elec.PublicKey.Y, 10)

	bsPK, _ := new(big.Int).SetString(b.Signature.PublicKey, 10)

	for ia, a := range b.Answers {
		// [4.12] Proofs
		// P = "g,y,alpha,beta,aSum,bSum"

		// Homomorphic Sum
		aSum := big.NewInt(1)
		bSum := big.NewInt(1)
		for i, c := range a.Choices {
			if elec.Questions[ia].Blank == true && i == 0 {
				continue
			}
			alpha, _ := new(big.Int).SetString(c.Alpha, 10)
			aSum = aSum.Mul(aSum, alpha).Mod(aSum, prime)
			beta, _ := new(big.Int).SetString(c.Beta, 10)
			bSum = bSum.Mul(bSum, beta).Mod(bSum, prime)

		}

		tc := big.NewInt(0) // total challenges

		HString := "" // signature

		if elec.Questions[ia].Blank == true {
			// [4.12.1] overall_proof signature with blank
			// SUM256("bproof0|public_key|P|A0,B0,A1,B1, A.., B..) mod q
			HString = fmt.Sprintf("bproof1|%s|", bsPK)
		} else {
			// [4.10.1] overall_proof signature without blank : prove interval
			// iprove(S,R,M−min,min,...,max)
			// [4.11] "prove|S|α,β|A0,B0,...,Ak,Bk"
			HString = fmt.Sprintf("prove|%s|%s,%s|", bsPK, aSum, bSum)
		}

		// A0, B0 for Question with blank
		if elec.Questions[ia].Blank == true {
			alpha0, _ := new(big.Int).SetString(a.Choices[0].Alpha, 10)
			beta0, _ := new(big.Int).SetString(a.Choices[0].Beta, 10)
			r0, _ := new(big.Int).SetString(a.OverallProof[0].Response, 10)
			c0, _ := new(big.Int).SetString(a.OverallProof[0].Challenge, 10)

			tc = c0

			// [4.12] Proofs
			// P = "g,y,alpha0,beta0,aS,bS"
			P := fmt.Sprintf("%s,%s,%s,%s,%s,%s", g, y, alpha0, beta0, aSum, bSum)
			HString += fmt.Sprintf("%s|", P)

			// [4.12.3] Verifyink overall_proof
			// A0 = g**response0 x alpha0**challenge0
			// B0 = y**response0 x (beta0/g)**challenge0
			a0a := new(big.Int).Exp(g, r0, prime)
			a0b := new(big.Int).Exp(alpha0, c0, prime)
			A0 := a0a.Mul(a0a, a0b)
			A0 = A0.Mod(A0, prime)

			b0a := new(big.Int).Exp(y, r0, prime)
			b0Dg := new(big.Int).Mul(beta0, new(big.Int).ModInverse(g, prime))
			b0b := new(big.Int).Exp(b0Dg, c0, prime)
			B0 := b0a.Mul(b0a, b0b)
			B0 = B0.Mod(B0, prime)

			// Add A0, B0
			HString += fmt.Sprintf("%s,%s,", A0, B0)

		}

		M := ""
		min := elec.Questions[ia].Min
		max := elec.Questions[ia].Max

		for k := min; k <= max; k++ {
			im := k - min // challenge, response array index
			if elec.Questions[ia].Blank == true {
				im += 1 // Blank vote is stored in head of array
			}
			r, _ := new(big.Int).SetString(a.OverallProof[im].Response, 10)
			c, _ := new(big.Int).SetString(a.OverallProof[im].Challenge, 10)

			// ( challenge0 + challenge1 + challenge.. ) mod q
			tc = tc.Mod(tc.Add(tc, c), q)

			// [4.12.3] Verifyink overall_proof
			// A = g**response x alpha**challenge
			// B = y**response x (beta/(g**k))**challenge
			// [4.10.1] Interval for non blank
			// A = g**response / alpha**challenge
			// B = y**response / (beta/(g**k))**challenge
			a1a := new(big.Int).Exp(g, r, prime)    // g**response
			a1b := new(big.Int).Exp(aSum, c, prime) // alpha**challenge

			mBigInt := big.NewInt(int64(k))
			gEm := new(big.Int).Exp(g, mBigInt, prime)                          // g**k
			b1a := new(big.Int).Exp(y, r, prime)                                // y**response
			b1Dg := new(big.Int).Mul(bSum, new(big.Int).ModInverse(gEm, prime)) // 1/(g**k)
			b1b := new(big.Int).Exp(b1Dg, c, prime)                             // (beta/(g**k))**challenge

			A := big.NewInt(1)
			B := big.NewInt(1)
			if elec.Questions[ia].Blank == true {
				// [4.12.3] Verifyink overall_proof
				A = a1a.Mul(a1a, a1b)
				B = b1a.Mul(b1a, b1b)
			} else {
				// [4.10.1] Interval for non blank
				A = a1a.Mul(a1a, new(big.Int).ModInverse(a1b, prime))
				B = b1a.Mul(b1a, new(big.Int).ModInverse(b1b, prime))
			}
			A = A.Mod(A, prime)
			B = B.Mod(B, prime)

			// Add A0,B0,...,Am,Bm for prove
			//  or A0,B0,...,Am,Bm for bproof1
			M += fmt.Sprintf(",%s,%s", A, B)
		}

		HString += M[1:] // M[1:] Remove first ","

		// SUM256("...") mod q
		hashS := sha256.Sum256([]byte(HString))
		bHashS := new(big.Int).SetBytes(hashS[:])
		left := bHashS.Mod(bHashS, q)

		// ( challenge0 + challenge1 + challenge ..) mod q
		right := tc

		if left.Cmp(right) == 0 {
			OK("")
		} else {
			return fmt.Errorf(" Overall Proof answer %d\n   K0 !!!!!\n%s", ia+1, b.Signature.Challenge)
		}
	}

	return nil // no error
}

func verifyDecryptedResults(a, b [][]int) error {
	if len(a) != len(b) {
		return fmt.Errorf(" not matching length\n    decrypted: %+v\n results.json: %+v\n", a, b)
	}
	for i1, v1 := range a {
		for i2, v2 := range v1 {
			if len(v1) != len(b[i1]) {
				return fmt.Errorf(" not matching length\n    decrypted: %+v\n results.json: %+v\n", a, b)
			}
			if v2 != b[i1][i2] {
				return fmt.Errorf(" not matching values\n    decrypted: %+v\n results.json: %+v\n", a, b)
			}
		}
	}
	return nil
}
