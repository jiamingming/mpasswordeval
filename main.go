package main

import (
	"encoding/json"
	"fmt"
	"github.com/jiamingming/mpasswordeval/verifier"
)

/**
 *main
 *@author: jiamingm
 *@date: 2021/11/4 13:54
 *@tips:
 */

func main() {

	//pwd := `PassW0rd`
	//pwd := `123456789asdcvbnm`
	//pwd := `Pa@zzWord`
	//pwd := `freepass12324`
	//pwd := `111111111111`
	//pwd := `password`
	//pwd := `mnbvc123456xzasd`
	pwd := "bvcxzaqwe"

	mpeval := &verifier.MPasswordEval{
		Digit:   true,
		Upper:   true,
		Lower:   true,
		Special: true,
		Zxcvbn:  true,
		Pwned:   false,
		TopDict: true,
		Length:  8,
	}

	coreVerify, err2 := mpeval.CoreVerify(pwd)
	jsonv, _ := json.Marshal(coreVerify)
	fmt.Println(string(jsonv), err2)

}
