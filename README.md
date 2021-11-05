# mpasswordeval
eval the strength of a password - 评估密码强度


校验密码的安全性  
包含以下几点校验， 其中每项规则可单独开启或关闭

常规规则校验
* 密码长度 （必须指定）
* 是否包含数字
* 是否包含大写字母
* 是否包含小写字母
* 是否包含特殊符号  
* 是否在常用弱密码 (指定的弱密码集)  

加强规则校验
* 是否通过zxcvbn （密码强度估计器）
* 是否通过pwned （泄漏密码库  https://haveibeenpwned.com/ 提供的api）



使用示例  
go get github.com/jiamingming/mpasswordeval  

```


        //测试密码
        pwd := `Ming2021jshbd`
        //指定规则
	mpeval := &verifier.MPasswordEval{
		Digit: true,
		Upper: true,
		Lower: true,
		Special: true,
		Zxcvbn:  true,
		Pwned:   true,
		TopDict: true,
		Length: 8,

	}
        //获取结果
	coreVerify, err2 := mpeval.CoreVerify(pwd)
	jsonv, _ := json.Marshal(coreVerify)
	fmt.Println(string(jsonv), err2)


```

响应结果示例  
* status 最终结果， true 代表通过检查， false 代表未通过检查
* verify_item 每项检查结果
```
{
	"verify_item": {
		"zxcv": true,
		"pwned": true,
		"top_dict": true,
		"common_strategy": {
			"is_digit": true,
			"is_upper": true,
			"is_lower": true,
			"is_special": false,
			"pwd_length": true
		}
	},
	"message": "",
	"status": false
}


```

