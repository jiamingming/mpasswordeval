package verifier

import (
	"unicode"
)

/**
 *common
 *@author: jiamingm
 *@date: 2021/11/4 19:00
 *@tips:
 */

func (mpe *MPasswordEval) CommonVerify(pwd string) *CommonStrategy {

	common := &CommonStrategy{}

	for _, v := range pwd {

		if (unicode.IsDigit(v) && mpe.Digit) || !mpe.Digit {
			common.IsDigit = true
		}
		if (unicode.IsUpper(v) && mpe.Upper) || !mpe.Upper {
			common.IsUpper = true
		}
		if (unicode.IsLower(v) && mpe.Lower) || !mpe.Lower {
			common.IsLower = true
		}
		if ((unicode.IsSymbol(v) || unicode.IsPunct(v)) && mpe.Special) || !mpe.Special {
			common.IsSpecial = true
		}

		if len(pwd) >= mpe.Length {
			common.PwdLength = true
		} else {
			common.PwdLength = false
		}

	}

	return common
}
