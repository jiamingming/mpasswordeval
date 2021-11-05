package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/nbutton23/zxcvbn-go/adjacency"
	"github.com/nbutton23/zxcvbn-go/match"
)

/**
 *zxcvbn
 *@author: jiamingm
 *@date: 2021/11/4 15:18
 *@tips:
 */

var (
	dictionaryMatchers []match.Matcher
	matchers           []match.Matcher
	adjacencyGraphs    []adjacency.Graph
	l33tTable          adjacency.Graph

	sequences map[string]string
)

const (
	spatialMatcherName        = "SPATIAL"
	L33TMatcherName           = "l33t"
	repeatMatcherName         = "REPEAT"
	sequenceMatcherName       = "SEQ"
	dateSepMatcherName        = "DATESEP"
	dateWithOutSepMatcherName = "DATEWITHOUT"
)

func isablespetial(matcher match.Matcher) bool {
	if matcher.ID == spatialMatcherName {
		return false
	}
	if matcher.ID == repeatMatcherName {
		return false
	}
	if matcher.ID == sequenceMatcherName {
		return false
	}
	if matcher.ID == "Passwords" {
		return false
	}

	return true
}
func (mpe *MPasswordEval) ZxcvbnVerify(pwd string) (bool, string, error) {

	result := zxcvbn.PasswordStrength(pwd, nil, isablespetial)
	//result := zxcvbn.PasswordStrength(pwd, nil)

	errMsg := ""

	zxcvbn, _ := json.Marshal(result)
	fmt.Println(string(zxcvbn))
	//fmt.Println(result.CalcTime, result.CrackTime, result.Score, result.Entropy)
	//Score # [0,1,2,3,4] if crack time is less than # [10^2, 10^4, 10^6, 10^8, Infinity]. # (useful for implementing a strength bar.)
	if result.Score > 3 {
		return true, "", nil
	}
	sequence := result.MatchSequence
	for _, v := range sequence {
		if v.Pattern == "dictionary" {
			errMsg += " 密码属于常用易破解密码! "
		}
		if v.Pattern == "spatial" {
			errMsg += " 密码属于键盘连续输入! "
		}
		if v.Pattern == "sequence" {
			errMsg += " 密码属于连续序列! "
		}
		if v.Pattern == "repeat" {
			errMsg += " 密码包含重复输入! "
		}
	}

	return false, errMsg, errors.New(errMsg)

}
