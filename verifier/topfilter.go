package verifier

import "strings"

/**
 *topfilter
 *@author: jiamingm
 *@date: 2021/11/4 18:21
 *@tips: 常见字典中检索
 */

func (mpe *MPasswordEval) TopDictFilter(pwd string) (bool, string, error) {

	if strings.Contains(Top1000Pwd, pwd) {
		return false, "", nil
	} else {
		return true, "", nil
	}

}
