package main


type Result struct {
	NumTallied     int `json:"num_tallied"`
	EncryptedTally [][]struct {
		Alpha string `json:"alpha"`
		Beta  string `json:"beta"`
	} `json:"encrypted_tally"`
	PartialDecryptions []struct {
		DecryptionFactors [][]string `json:"decryption_factors"`
		DecryptionProofs  [][]struct {
			Challenge string `json:"challenge"`
			Response  string `json:"response"`
		} `json:"decryption_proofs"`
	} `json:"partial_decryptions"`
	Result [][]int `json:"result"`
}

type Election struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	PublicKey   struct {
		Group struct {
			G string `json:"g"`
			P string `json:"p"`
			Q string `json:"q"`
		} `json:"group"`
		Y string `json:"y"`
	} `json:"public_key"`
	Questions []struct {
		Answers  []string `json:"answers"`
		Blank    bool     `json:"blank,omitempty"`
		Min      int      `json:"min"`
		Max      int      `json:"max"`
		Question string   `json:"question"`
	} `json:"questions"`
	UUID                string `json:"uuid"`
	Administrator       string `json:"administrator"`
	CredentialAuthority string `json:"credential_authority"`
}

type Ballot struct {
	Answers []struct {
		Choices []struct {
			Alpha string `json:"alpha"`
			Beta  string `json:"beta"`
		} `json:"choices"`
		IndividualProofs [][]struct {
			Challenge string `json:"challenge"`
			Response  string `json:"response"`
		} `json:"individual_proofs"`
		OverallProof []struct {
			Challenge string `json:"challenge"`
			Response  string `json:"response"`
		} `json:"overall_proof"`
		BlankProof []struct {
			Challenge string `json:"challenge"`
			Response  string `json:"response"`
		} `json:"blank_proof"`
	} `json:"answers"`
	ElectionHash string `json:"election_hash"`
	ElectionUUID string `json:"election_uuid"`
	Signature    struct {
		PublicKey string `json:"public_key"`
		Challenge string `json:"challenge"`
		Response  string `json:"response"`
	} `json:"signature"`
}

