package parse

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/michael/vless-sub-server/internal/config"
)

var proxySchemes = []string{"vless://", "vmess://", "trojan://", "ss://"}

type ParseResult struct {
	Records   []ProxyRecord
	Skipped   int
	Duplicates int
}

func ParseAllLines(lines []string) ParseResult {
	seen := map[string]bool{}
	var records []ProxyRecord
	skipped, duplicates := 0, 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			skipped++
			continue
		}

		matched := false
		for _, s := range proxySchemes {
			if strings.HasPrefix(trimmed, s) {
				matched = true
				break
			}
		}
		if !matched {
			skipped++
			continue
		}

		var record *ProxyRecord
		switch {
		case strings.HasPrefix(trimmed, "vless://"):
			record = parseVless(trimmed)
		case strings.HasPrefix(trimmed, "vmess://"):
			record = parseVMess(trimmed)
		case strings.HasPrefix(trimmed, "trojan://"):
			record = parseTrojan(trimmed)
		case strings.HasPrefix(trimmed, "ss://"):
			record = parseSS(trimmed)
		}

		if record == nil || record.Host == "" || record.Port <= 0 || record.Port > 65535 {
			skipped++
			continue
		}

		if config.PlaceholderHosts[record.Host] {
			skipped++
			continue
		}

		key := record.Host + ":" + strconv.Itoa(record.Port) + ":" + string(record.Protocol) + ":" + record.UUIDOrPassword
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		records = append(records, *record)
	}

	return ParseResult{Records: records, Skipped: skipped, Duplicates: duplicates}
}

func ApplyNameFilter(records []ProxyRecord, include, exclude string) []ProxyRecord {
	filtered := records
	if exclude != "" {
		result := filtered[:0]
		for _, r := range filtered {
			if !strings.Contains(r.Fragment, exclude) {
				result = append(result, r)
			}
		}
		filtered = result
	}
	if include != "" {
		result := filtered[:0]
		for _, r := range filtered {
			if strings.Contains(r.Fragment, include) {
				result = append(result, r)
			}
		}
		filtered = result
	}
	return filtered
}

func parseVless(line string) *ProxyRecord {
	cleaned := strings.TrimRight(line, "\\")
	u, err := url.Parse(cleaned)
	if err != nil {
		return nil
	}
	port := 443
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	params := map[string]string{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		} else {
			params[k] = ""
		}
	}
	normalizeInsecure(params)

	return &ProxyRecord{
		Protocol:       VLESS,
		Host:           u.Hostname(),
		Port:           port,
		UUIDOrPassword: u.User.Username(),
		QueryParams:    params,
		Fragment:       u.Fragment,
		OriginalLine:   line,
	}
}

func parseVMess(line string) *ProxyRecord {
	encoded := line[len("vmess://"):]
	encoded = strings.ReplaceAll(encoded, "-", "+")
	encoded = strings.ReplaceAll(encoded, "_", "/")
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}

	var cfg struct {
		V             string `json:"v"`
		Host          string `json:"add"`
		Port          any    `json:"port"`
		ID            string `json:"id"`
		PS            string `json:"ps"`
		Net           string `json:"net"`
		Type          string `json:"type"`
		TLS           string `json:"tls"`
		SNI           string `json:"sni"`
		Path          string `json:"path"`
		Host2         string `json:"host"`
		Flow          string `json:"flow"`
		Scy           string `json:"scy"`
		Alpn          string `json:"alpn"`
		FP            string `json:"fp"`
		PBK           string `json:"pbk"`
		SID           string `json:"sid"`
		SPX           string `json:"spx"`
		AllowInsecure bool   `json:"allowInsecure"`
	}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil
	}

	if cfg.V != "" && cfg.V != "2" {
		return nil
	}

	// Port can be int or string
	port := 0
	switch p := cfg.Port.(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	}

	params := map[string]string{}
	if cfg.Net != "" {
		params["type"] = cfg.Net
	}
	if cfg.TLS == "tls" {
		params["security"] = "tls"
	} else if cfg.TLS == "reality" {
		params["security"] = "reality"
	}
	if cfg.SNI != "" {
		params["sni"] = cfg.SNI
	}
	if cfg.Path != "" {
		params["path"] = cfg.Path
	}
	if cfg.Host2 != "" {
		params["host"] = cfg.Host2
	}
	if cfg.Flow != "" {
		params["flow"] = cfg.Flow
	}
	if cfg.Type != "" && cfg.Type != "none" {
		params["headerType"] = cfg.Type
	}
	if cfg.Scy != "" {
		params["scy"] = cfg.Scy
	}
	if cfg.Alpn != "" {
		params["alpn"] = cfg.Alpn
	}
	if cfg.FP != "" {
		params["fp"] = cfg.FP
	}
	if cfg.PBK != "" {
		params["pbk"] = cfg.PBK
	}
	if cfg.SID != "" {
		params["sid"] = cfg.SID
	}
	if cfg.SPX != "" {
		params["spx"] = cfg.SPX
	}
	if cfg.AllowInsecure {
		params["insecure"] = "1"
	}
	normalizeInsecure(params)

	return &ProxyRecord{
		Protocol:       VMess,
		Host:           cfg.Host,
		Port:           port,
		UUIDOrPassword: cfg.ID,
		QueryParams:    params,
		Fragment:       cfg.PS,
		OriginalLine:   line,
	}
}

func parseTrojan(line string) *ProxyRecord {
	u, err := url.Parse(line)
	if err != nil {
		return nil
	}
	if u.User == nil {
		return nil
	}
	port := 443
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	password := u.User.Username()
	if p, ok := u.User.Password(); ok {
		password += ":" + p
	}
	params := map[string]string{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		} else {
			params[k] = ""
		}
	}
	normalizeInsecure(params)

	return &ProxyRecord{
		Protocol:       Trojan,
		Host:           u.Hostname(),
		Port:           port,
		UUIDOrPassword: password,
		QueryParams:    params,
		Fragment:       u.Fragment,
		OriginalLine:   line,
	}
}

func parseSS(line string) *ProxyRecord {
	encoded := line[len("ss://"):]
	hashIdx := strings.Index(encoded, "#")
	var fragment, main string
	if hashIdx != -1 {
		fragment = encoded[hashIdx+1:]
		main = encoded[:hashIdx]
	} else {
		main = encoded
	}

	atIdx := strings.LastIndex(main, "@")
	if atIdx == -1 {
		return nil
	}
	methodPassword := main[:atIdx]
	hostPort := main[atIdx+1:]

	colonIdx := strings.Index(methodPassword, ":")
	if colonIdx == -1 {
		return nil
	}
	method := methodPassword[:colonIdx]
	password := methodPassword[colonIdx+1:]

	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon == -1 {
		return nil
	}
	host := hostPort[:lastColon]
	port, err := strconv.Atoi(hostPort[lastColon+1:])
	if err != nil {
		return nil
	}

	return &ProxyRecord{
		Protocol:       SS,
		Host:           host,
		Port:           port,
		UUIDOrPassword: password,
		QueryParams:    map[string]string{"method": method},
		Fragment:       fragment,
		OriginalLine:   line,
	}
}

func normalizeInsecure(params map[string]string) {
	val := params["allowInsecure"]
	if val == "" {
		val = params["insecure"]
	}
	if val == "" {
		val = params["allow_insecure"]
	}
	if val != "" {
		params["insecure"] = "1"
	}
	delete(params, "allowInsecure")
	delete(params, "allow_insecure")
}
