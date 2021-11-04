package verifier

import (
	"errors"
	"fmt"
	"github.com/nbutton23/zxcvbn-go"
)

/**
 *zxcvbn
 *@author: jiamingm
 *@date: 2021/11/4 15:18
 *@tips:
 */

type Zxcvbn struct {
}

func (z *Zxcvbn) ZxcvbnVerify(password string) (bool, string, error) {

	result := zxcvbn.PasswordStrength(password, nil)
	fmt.Println(result.CalcTime, result.CrackTime, result.Score, result.Entropy)
	//Score # [0,1,2,3,4] if crack time is less than # [10^2, 10^4, 10^6, 10^8, Infinity]. # (useful for implementing a strength bar.)
	if result.Score > 3 {
		return true, "", nil
	}
	return false, "", errors.New("")

}
