// 错误定义

package apicsrf

import (
	"github.com/go-apibox/api"
)

// error type
const (
	errorSessionInitFailed = iota
	errorSessionGetFailed
	errorCSRFTokenError
)

var ErrorDefines = map[api.ErrorType]*api.ErrorDefine{
	errorSessionInitFailed: api.NewErrorDefine(
		"SessionInitFailed",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Session init failed!",
			},
			"zh_cn": {
				0: "会话初始化失败！",
			},
		},
	),
	errorSessionGetFailed: api.NewErrorDefine(
		"SessionGetFailed",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Failed to get session!",
			},
			"zh_cn": {
				0: "会话获取失败！",
			},
		},
	),
	errorCSRFTokenError: api.NewErrorDefine(
		"CSRFTokenError",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "CSRF token error!",
			},
			"zh_cn": {
				0: "CSRF验证失败！",
			},
		},
	),
}
