package verifier

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/errors"
)

/**
 *pwned
 *@author: jiamingm
 *@date: 2021/11/4 17:27
 *@tips:
 */

const baseURL = "https://api.pwnedpasswords.com/range/"

var (
	ErrStringEmpty = errors.New("Empty password string error")
	ErrNonHTTPOk   = errors.New("Non HTTP OK in API Call")
)

// PwnedVerify
// In order to protect the value of the source password being searched for,
// Pwned Passwords also implements a k-Anonymity model that allows a password
// to be searched for by partial hash. This allows the first 5 characters
// of a SHA-1 password hash (not case-sensitive) to be passed to the API (testable by clicking here):
// GET https://api.pwnedpasswords.com/range/{first 5 hash chars}
func (mpe *MPasswordEval) PwnedVerify(pwd string) (bool, string, error) {
	// error if rune count is 0 (or less ?)
	if utf8.RuneCountInString(pwd) <= 0 {
		return false, "", ErrStringEmpty
	}

	// construct a new http.Client if not already supplied
	if mpe.HTTPClient == nil {
		mpe.HTTPClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	// compute sha1
	data := []byte(pwd)
	hash := sha1.Sum(data)

	// get prefix suffix
	hex := strings.ToUpper(hex.EncodeToString(hash[0:]))
	prefix := hex[0:5]
	suffix := hex[5:]

	// hit the API
	fullURL := baseURL + prefix
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return false, "", errors.Wrap(err, "fail in creating new http request")
	}

	// be a friendly client and tell the API who are you
	req.Header.Set("User-Agent", "github.com/jiamingming/mpasswordeval")

	resp, err := mpe.HTTPClient.Do(req)
	if err != nil {
		return false, "", errors.Wrap(err, "http api call failure")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", ErrNonHTTPOk
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "fail in reading response body")
	}

	//fmt.Println("the pwned response: ", string(body))
	// check suffix in response body
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		tokens := strings.Split(line, ":")
		// if it matches with the API response, return as not safe
		if suffix == tokens[0] {
			occurence := string(tokens[1])
			return false, fmt.Sprintf("shows in pwnedpasswords with occurence: %s", occurence), nil
		}
	}

	// if the suffix doesn't match with any API response data, return as safe
	return true, "", nil
}
