package main

import (
	"fmt"
	"mpasswordeval/verifier"
)

/**
 *main
 *@author: jiamingm
 *@date: 2021/11/4 13:54
 *@tips:
 */

func main() {

	zxcvbn := &verifier.Zxcvbn{}
	verify, s, err := zxcvbn.ZxcvbnVerify("PassWord123")
	fmt.Println(verify, s, err)

}
