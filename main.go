package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/gookit/color"
	"github.com/schollz/progressbar/v3"
)

var (
	bar     *progressbar.ProgressBar
	Version string
	Test    bool
)

/**
 Tools
**/

func OK(msg string) {
	if msg != "" {
		fmt.Println(msg)
	}
	if Test == false {
		bar.Add(1)
	}
}

func Error(msg string) {
	fmt.Println()
	color.Printf("<error>ERROR</>\t%s\n", msg)
	os.Exit(0)
}

func IsEmptyDir(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// read Data from json files
func readData(files [4]string, dir string) (Election, Result, []Ballot) {
	var (
		elec    Election
		res     Result
		ballots []Ballot
	)
	for _, file := range files {
		jsonFile, err := os.Open(dir + "/" + file)
		if err != nil {
			Error(fmt.Sprintf("%s\n", err.Error()))
		}
		defer jsonFile.Close()

		switch file {
		case "election.json":
			byteValue, _ := ioutil.ReadAll(jsonFile)
			json.Unmarshal(byteValue, &elec)
		case "result.json":
			byteValue, _ := ioutil.ReadAll(jsonFile)
			json.Unmarshal(byteValue, &res)
		case "ballots.jsons": // one json ballot by line
			scanner := bufio.NewScanner(jsonFile)
			for scanner.Scan() {
				var b Ballot
				json.Unmarshal(scanner.Bytes(), &b)
				ballots = append(ballots, b)
			}
		}
	}

	return elec, res, ballots
}

// describe Election
// return : fingerprint, number of tests
func describeElection(elec Election) (string, int) {
	// [4.14] fingerprint of election
	//  HJSON(J) = BASE64(SHA256(J))
	J, _ := json.Marshal(elec)
	hashJ := sha256.Sum256(J)
	HJSON := base64.RawStdEncoding.EncodeToString(hashJ[:])

	/**
	Count tests for progression bar
	**/
	tests := 0
	for _, q := range elec.Questions {
		btest := len(q.Answers) //IndividualProofs
		if q.Blank == true {    // BlankProof
			btest += 2 // 1 blank + 1 individual
		}
		tests += btest
	}
	tests += 3 // Hash election + Signature + overall

	if Test == false {
		fmt.Println("\n= ", elec.Name, " =")
		fmt.Println(elec.Description)
		fmt.Println()
		fmt.Printf("ID : %s\n", elec.UUID)
		fmt.Printf("Admin : %s\n", elec.Administrator)
		fmt.Printf("Credential Authority : %s\n", elec.CredentialAuthority)
		fmt.Printf("Fingerprint : %s\n\n", HJSON)
		fmt.Printf("Question(s) : %d\n", len(elec.Questions))
	}
	return HJSON, tests
}

// Download and verify ballot
func validateOnlineBallot(surl string, bhash string) error {
	// Download ballot
	u, _ := url.Parse(surl)
	fmt.Printf("Download ballot: %s\n", bhash)
	path := u.Path
	burl := url.URL{Scheme: u.Scheme, Host: u.Host, Path: path + "/ballot"}
	q := burl.Query()
	q.Set("hash", bhash)
	burl.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", burl.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Error(err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		Error(fmt.Sprintf("GET %s (HTTP status: %d)", req.URL, resp.StatusCode))
	}
	byteValue, _ := ioutil.ReadAll(resp.Body)
	var b Ballot
	json.Unmarshal(byteValue, &b)

	// Download election.json
	uelec := url.URL{Scheme: u.Scheme, Host: u.Host, Path: path + "/election.json"}
	fmt.Printf("Download %s\n", uelec.String())
	req, _ = http.NewRequest("GET", uelec.String(), nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		Error(err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		Error(fmt.Sprintf("GET %s (HTTP status: %d)", req.URL, resp.StatusCode))
	}
	byteValue, _ = ioutil.ReadAll(resp.Body)
	var elec Election
	json.Unmarshal(byteValue, &elec)

	// Print global description
	HJSON, tests := describeElection(elec)
	bar = progressbar.Default(int64(tests))

	// Ballot verifications
	fmt.Printf("\nBallot verifications:\n\n")
	err = verifyResponseToElection(b, elec.UUID, HJSON)
	if err != nil {
		Error(err.Error())
	}
	err = verifyBallotSignature(b, elec)
	if err != nil {
		Error(err.Error())
	}
	err = verifyBallotBlankProofs(b, elec)
	if err != nil {
		if err.Error() != "" { // for question without blank
			Error(err.Error())
		}
	}
	err = verifyBallotOverallProofs(b, elec)
	if err != nil {
		Error(err.Error())
	}
	err = verifyBallotIndividualProofs(b, elec)
	if err != nil {
		Error(err.Error())
	}
	return nil
}

/**
 main cli
**/

func main() {
	banner := `
______                       
| ___ \                      
| |_/ / ___  _ ____   _____  
| ___ \/ _ \| '__\ \ / / _ \ 
| |_/ / (_) | |   \ V / (_) |
\____/ \___/|_|    \_/ \___/ 
`
	color.Info.Println(banner)
	fmt.Println("A tool to verify Belenios homomorphic election")
	fmt.Printf("%s\n\n", Version)

	files := [4]string{"election.json", "result.json", "ballots.jsons", "trustees.json"}

	/**
	Manage flags
	**/
	fbhash := flag.String("b", "", "Online ballot hash (need url)")
	fdir := flag.String("dir", "", "Directory with files to audit")
	furl := flag.String("url", "", "Election url to download files")
	flag.Parse()

	bhash := *fbhash
	dir := *fdir
	url := *furl

	var re = regexp.MustCompile(`[/ ]$`) // clean last "/"
	url = re.ReplaceAllString(url, "")

	// Download and verify online ballot
	if bhash != "" && url != "" {
		err := validateOnlineBallot(url, bhash)
		if err != nil {
			Error(err.Error())
		}
		color.Printf("<suc>OK</>\n\n")
		os.Exit(0)
	}

	// Test directory to store files
	if dir == "" { // useless paranoiac test (managed by flag)
		flag.PrintDefaults()
		fmt.Println()
		os.Exit(0)
	}

	isEmpty, err := IsEmptyDir(dir)
	if err != nil {
		Error(err.Error())
	}

	/**
	Download online files
	**/
	if url != "" {
		if isEmpty == false { // mandatory empty dir for download
			Error(fmt.Sprintf("Not empty directory «%s»", dir))
		}

		fmt.Println("Download")
		for _, fname := range files {
			req, _ := http.NewRequest("GET", url+"/"+fname, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				Error(err.Error())
			}
			if resp.StatusCode != http.StatusOK {
				Error(fmt.Sprintf("GET %s (HTTP status: %d)", req.URL, resp.StatusCode))
			}
			defer resp.Body.Close()

			f, _ := os.OpenFile(dir+"/"+fname, os.O_CREATE|os.O_WRONLY, 0644)
			defer f.Close()

			barf := progressbar.DefaultBytes(
				resp.ContentLength,
				fmt.Sprintf("downloading %s", fname),
			)
			io.Copy(io.MultiWriter(f, barf), resp.Body)
		}
		fmt.Printf("\n\n")
	}

	/**
	Read files
	**/

	elec, res, ballots := readData(files, dir)

	/**
	Process election
	**/

	// Print global description
	HJSON, tests := describeElection(elec)

	color.Printf("Ballots : <suc>%d</>\n", len(ballots))

	bar = progressbar.Default(int64(tests * len(ballots)))

	// Ballots verifications
	fmt.Printf("\nBallots verifications:\n\n")
	for _, b := range ballots {
		err := verifyResponseToElection(b, elec.UUID, HJSON)
		if err != nil {
			Error(err.Error())
		}
		err = verifyBallotSignature(b, elec)
		if err != nil {
			Error(err.Error())
		}
		err = verifyBallotBlankProofs(b, elec)
		if err != nil {
			if err.Error() != "" { // for question without blank
				Error(err.Error())
			}
		}
		err = verifyBallotOverallProofs(b, elec)
		if err != nil {
			Error(err.Error())
		}
		err = verifyBallotIndividualProofs(b, elec)
		if err != nil {
			Error(err.Error())
		}

	}

	// Count, Decrypt, Print
	fmt.Printf("\nBallots homomorphic count ...\n")
	count := Count(elec, ballots)
	err, results := DecryptResults(elec, res, count)
	if err == nil {
		fmt.Printf("\nDecrypted Results: ")
		e := verifyDecryptedResults(results, res.Result)
		if e != nil {
			Error(e.Error())
		}
		color.Printf("<suc>OK</>\n\n")
		PrintNewResults(elec, results)
	}

	fmt.Println()

}
