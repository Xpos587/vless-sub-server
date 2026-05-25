package format

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

type FormatMetadata struct {
	TotalFetched  int
	TotalParsed   int
	TotalSkipped int
	TotalDuplicates int
	TotalAlive    int
	TotalDead     int
	SourcesOK     int
	SourcesFailed int
	GeoAvailable  int
	GeoTotal      int
}

func FormatOutput(entries []rename.RenamedEntry, meta FormatMetadata) string {
	var lines []string

	now := time.Now().UTC().Add(3 * time.Hour)
	dateStr := now.Format("2006-01-02 / 15:04:05") + " (Moscow)"

	lines = append(lines, "# profile-title: Proxy Subscription Parser")
	lines = append(lines, "# profile-update-interval: 1")
	lines = append(lines, fmt.Sprintf("# Date/Time: %s", dateStr))
	lines = append(lines, fmt.Sprintf("# Количество: %d", meta.TotalAlive))
	lines = append(lines, fmt.Sprintf("# Sources: %d ok, %d failed", meta.SourcesOK, meta.SourcesFailed))
	lines = append(lines, fmt.Sprintf("# Parsed: %d valid, %d skipped, %d duplicates", meta.TotalParsed, meta.TotalSkipped, meta.TotalDuplicates))
	probedTotal := meta.TotalAlive + meta.TotalDead
	lines = append(lines, fmt.Sprintf("# Probed: %d total, %d alive, %d dead", probedTotal, meta.TotalAlive, meta.TotalDead))
	lines = append(lines, fmt.Sprintf("# Geo: available for %d/%d", meta.GeoAvailable, meta.GeoTotal))
	lines = append(lines, "---")

	for _, e := range entries {
		lines = append(lines, reconstructURL(e.Record, e.RenamedFragment))
	}
	return strings.Join(lines, "\n")
}

func reconstructURL(record parse.ProxyRecord, fragment string) string {
	switch record.Protocol {
	case parse.VLESS:
		return reconstructVless(record, fragment)
	case parse.VMess:
		return reconstructVMess(record, fragment)
	case parse.Trojan:
		return reconstructTrojan(record, fragment)
	case parse.SS:
		return reconstructSS(record, fragment)
	default:
		return record.OriginalLine
	}
}

func formatHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func reconstructVless(record parse.ProxyRecord, fragment string) string {
	params := url.Values{}
	for k, v := range record.QueryParams {
		params.Set(k, v)
	}
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	userinfo := url.User(record.UUIDOrPassword).String()
	return fmt.Sprintf("vless://%s@%s:%d?%s%s", userinfo, formatHost(record.Host), record.Port, params.Encode(), frag)
}

func reconstructVMess(record parse.ProxyRecord, fragment string) string {
	vmConfig := map[string]any{
		"v":    "2",
		"ps":   fragment,
		"add":  record.Host,
		"port": record.Port,
		"id":   record.UUIDOrPassword,
		"net":  record.QueryParams["type"],
		"type": record.QueryParams["type"],
	}
	if record.QueryParams["security"] == "tls" {
		vmConfig["tls"] = "tls"
	} else {
		vmConfig["tls"] = ""
	}
	vmConfig["sni"] = record.QueryParams["sni"]
	vmConfig["path"] = record.QueryParams["path"]
	if vmConfig["path"] == "" {
		vmConfig["path"] = "/"
	}
	vmConfig["host"] = record.QueryParams["host"]

	jsonBytes, _ := json.Marshal(vmConfig)
	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	encoded = strings.TrimRight(encoded, "=")
	return "vmess://" + encoded
}

func reconstructTrojan(record parse.ProxyRecord, fragment string) string {
	params := url.Values{}
	for k, v := range record.QueryParams {
		params.Set(k, v)
	}
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	userinfo := url.User(record.UUIDOrPassword).String()
	return fmt.Sprintf("trojan://%s@%s:%d?%s%s", userinfo, formatHost(record.Host), record.Port, params.Encode(), frag)
}

func reconstructSS(record parse.ProxyRecord, fragment string) string {
	method := record.QueryParams["method"]
	if method == "" {
		method = "aes-256-gcm"
	}
	userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + record.UUIDOrPassword))
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	return fmt.Sprintf("ss://%s@%s:%d%s", userInfo, formatHost(record.Host), record.Port, frag)
}