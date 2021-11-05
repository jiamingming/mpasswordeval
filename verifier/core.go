package verifier

import "net/http"

/**
 *core
 *@author: jiamingm
 *@date: 2021/11/4 17:52
 *@tips:
 */

type MPasswordEval struct {
	HTTPClient *http.Client
	DictMap    map[string]int
	Pwned      bool //破解历史校验
	Zxcvbn     bool //zxcvbn校验
	TopDict    bool //常用字典校验
	Digit      bool //是否包含数字
	Upper      bool //是否包含大写字母
	Lower      bool //是否包含小写字母
	Special    bool //是否包含特殊符号
	Length     int  //密码长度
}

type MpasswordEvalResponse struct {
	VerifyItem *MpasswordEvalResponseItem `json:"verify_item"`
	Message    string                     `json:"message"`
	Status     bool                       `json:"status"`
}

type MpasswordEvalResponseItem struct {
	Zxcv           bool           `json:"zxcv"`
	Pwned          bool           `json:"pwned"`
	TopDict        bool           `json:"top_dict"`
	CommonStrategy CommonStrategy `json:"common_strategy"`
}

//常规策略
type CommonStrategy struct {
	IsDigit   bool `json:"is_digit"`   // 是否包含数字
	IsUpper   bool `json:"is_upper"`   // 是否包含大写字母
	IsLower   bool `json:"is_lower"`   // 是否包含小写字母
	IsSpecial bool `json:"is_special"` // 是否包含特殊符号
	PwdLength bool `json:"pwd_length"`
}

func (mpe *MPasswordEval) CoreVerify(pwd string) (*MpasswordEvalResponse, error) {

	response := &MpasswordEvalResponse{
		Status: true,
	}

	responseItem := &MpasswordEvalResponseItem{
		Zxcv:    true,
		Pwned:   true,
		TopDict: true,
	}

	responseMsg := ""
	// 常用字典校验
	if mpe.TopDict {
		filter, _, _ := mpe.TopDictFilter(pwd)
		if !filter {
			response.Status = false
		}
		responseItem.TopDict = filter
	}
	// zxcvbn 规则校验
	if mpe.Zxcvbn {
		zxcvbnverify, msg, _ := mpe.ZxcvbnVerify(pwd)
		if !zxcvbnverify {
			response.Status = false
			responseMsg += msg
		}
		responseItem.Zxcv = zxcvbnverify
	}

	// pwned 在线库校验
	if mpe.Pwned {
		pwnedverify, _, _ := mpe.PwnedVerify(pwd)
		if !pwnedverify {
			response.Status = false
		}
		responseItem.Pwned = pwnedverify
	}
	// 常规策略校验
	commonVerify := mpe.CommonVerify(pwd)
	// 密码长度
	if !commonVerify.PwdLength {
		response.Status = false
		responseMsg += " 密码长度不足!/ "
	}
	// 是否包含特殊符号
	if !commonVerify.IsSpecial {
		response.Status = false
		responseMsg += " 密码不包含特殊符号!/ "
	}
	// 是否包含数字
	if !commonVerify.IsDigit {
		response.Status = false
		responseMsg += " 密码不包含数字!/ "
	}
	// 是否包含大写字母
	if !commonVerify.IsUpper {
		response.Status = false
		responseMsg += " 密码不包含大写字母!/ "
	}
	// 是否包含小写字母
	if !commonVerify.IsLower {
		response.Status = false
		responseMsg += " 密码不包含小写字母!/ "
	}

	responseItem.CommonStrategy = *commonVerify

	response.VerifyItem = responseItem
	response.Message = responseMsg
	return response, nil

}
