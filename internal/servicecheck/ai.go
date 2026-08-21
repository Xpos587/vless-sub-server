package servicecheck

import (
	"context"
	"net/http"
	"strings"
)

// aiEndpoint describes one AI API reachability probe.
type aiEndpoint struct {
	id            string
	name          string
	url           string
	headers       map[string]string
	authStatus    []int
	regionMarkers []string
}

var aiCatalog = []aiEndpoint{
	{
		id:         "openai_api",
		name:       "OpenAI API",
		url:        "https://api.openai.com/v1/models",
		authStatus: []int{401},
		regionMarkers: []string{
			"unsupported_country_region_territory",
			"country, region, or territory not supported",
		},
	},
	{
		id:         "anthropic_api",
		name:       "Anthropic API",
		url:        "https://api.anthropic.com/v1/models",
		headers:    map[string]string{"anthropic-version": "2023-06-01"},
		authStatus: []int{401},
		regionMarkers: []string{
			"request not allowed",
			"unsupported_country",
		},
	},
	{
		id:         "gemini_api",
		name:       "Gemini API",
		url:        "https://generativelanguage.googleapis.com/v1beta/models",
		authStatus: []int{401, 403},
	},
	{
		id:         "deepseek_api",
		name:       "DeepSeek API",
		url:        "https://api.deepseek.com/models",
		authStatus: []int{401},
	},
	{
		id:         "qwen_intl_api",
		name:       "Qwen API (intl)",
		url:        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models",
		authStatus: []int{401},
	},
	{
		id:         "qwen_cn_api",
		name:       "Qwen API (CN)",
		url:        "https://dashscope.aliyuncs.com/compatible-mode/v1/models",
		authStatus: []int{401},
	},
	{
		id:         "moonshot_api",
		name:       "Kimi / Moonshot API",
		url:        "https://api.moonshot.cn/v1/models",
		authStatus: []int{401},
	},
	{
		id:         "zhipu_api",
		name:       "Zhipu GLM API",
		url:        "https://open.bigmodel.cn/api/paas/v4/models",
		authStatus: []int{401},
	},
}

func AICheckers() []Checker {
	out := make([]Checker, 0, len(aiCatalog))
	for _, e := range aiCatalog {
		out = append(out, e)
	}
	return out
}

func (e aiEndpoint) Name() string { return e.id }

func (e aiEndpoint) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, e.url, e.headers)
	if !r.ok {
		return requestFailure(e.id, r)
	}
	lower := strings.ToLower(r.body)
	if isChallenge(r.status, lower) {
		return Result{Service: e.id, Status: Unknown, Detail: "Cloudflare challenge"}
	}
	for _, m := range e.regionMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return Result{Service: e.id, Status: Blocked, Detail: "API refused this region"}
		}
	}
	for _, s := range e.authStatus {
		if r.status == s {
			return Result{Service: e.id, Status: Available, Detail: "API reachable"}
		}
	}
	return Result{Service: e.id, Status: Unknown, Detail: "unexpected response"}
}
