package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

//	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerify(t *testing.T) {
	Test = true

	files := [4]string{"election.json", "result.json", "ballots.jsons", "trustees.json"}
	elec, res, ballots := readData(files, "dataTest")

	//var s []byte
	//s, _ = json.MarshalIndent(ballots[0], "", " ")
	//fmt.Print("\n==Ballot 0==\n", string(s))
	//s, _ = json.MarshalIndent(elec, "", " ")
	//fmt.Print("\n==Élection==\n", string(s))
	//s, _ = json.MarshalIndent(res, "", " ")
	//fmt.Print("\n==Résultats==\n", string(s))

	jsonElec, _ := json.Marshal(elec)
	//fmt.Println(string(selec))
	hashJ := sha256.Sum256(jsonElec)
	HJSON := base64.RawStdEncoding.EncodeToString(hashJ[:])

	b := ballots[0]
	err := verifyResponseToElection(b, elec.UUID, HJSON)
	assert.Equal(t, nil, err, "Verify UUID and Hash")

	err = verifyBallotSignature(b, elec)
	assert.Equal(t, nil, err, "verifyBallotSignature")

	err = verifyBallotBlankProofs(b, elec)
	assert.Equal(t, nil, err, "verifyBallotBlankProofs")

	err = verifyBallotOverallProofs(b, elec)
	assert.Equal(t, nil, err, "verifyBallotOverallProofs")
	err = verifyBallotIndividualProofs(b, elec)
	assert.Equal(t, nil, err, "verifyBallotIndividualProofs")

	count := Count(elec, ballots)
	assert.Equal(t, 4, len(count), "4 Questions in Count")
	assert.Equal(t, 4, len(count[0]), "4 Answers in first Question")

	err, results := DecryptResults(elec, res, count)
	assert.Equal(t, nil, err, "DecryptAndPrint")
	assert.Equal(t, 4, len(results), "4 Questions in Count")
	assert.Equal(t, 4, len(results[0]), "4 Answers in first Question")

	err = verifyDecryptedResults(results, res.Result)
	assert.Equal(t, nil, err, "Same calculated results")

}
