package rename

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
)

type RenamedEntry struct {
	Record          parse.ProxyRecord
	RenamedFragment string
}

func CountryCodeToFlag(code string) string {
	if len(code) != 2 {
		return code
	}
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}

func RenameAll(records []struct {
	Record parse.ProxyRecord
	Geo    *geo.GeoInfo
	IsLAN  bool
}) []RenamedEntry {
	var entries []RenamedEntry
	nameCounts := map[string]int{}
	gatewayCounts := make(map[string]int, len(records))
	gatewayNames := make(map[string]map[string]struct{}, len(records))
	for _, record := range records {
		key := credentialGatewayKey(record.Record)
		gatewayCounts[key]++
		if record.Record.Fragment != "" {
			if gatewayNames[key] == nil {
				gatewayNames[key] = make(map[string]struct{})
			}
			gatewayNames[key][record.Record.Fragment] = struct{}{}
		}
	}

	for _, r := range records {
		var baseName string
		gatewayKey := credentialGatewayKey(r.Record)
		credentialRouted := gatewayCounts[gatewayKey] > 1 && len(gatewayNames[gatewayKey]) > 1
		if isAutoRoute(r.Record.Fragment) {
			baseName = credentialRouteName(r.Record.Fragment, r.Geo)
		} else if credentialRouted && r.Record.Fragment != "" {
			baseName = credentialRouteName(r.Record.Fragment, r.Geo)
		} else if r.Geo != nil {
			baseName = buildName(r.Geo)
		} else {
			name := r.Record.Fragment
			if name == "" {
				name = r.Record.Host
			}
			baseName = name
		}
		count := nameCounts[baseName]
		nameCounts[baseName] = count + 1

		finalName := baseName
		if count > 0 {
			finalName = fmt.Sprintf("%s (%d)", baseName, count+1)
		}
		entries = append(entries, RenamedEntry{Record: r.Record, RenamedFragment: finalName})
	}
	return entries
}

func credentialRouteName(fragment string, info *geo.GeoInfo) string {
	name := strings.TrimSpace(fragment)
	if isAutoRoute(name) {
		isp := "Unknown"
		if info != nil && info.ISP != "" {
			isp = info.ISP
		}
		return fmt.Sprintf("АВТОВЫБОР (%s)", isp)
	}
	if fields := strings.Fields(name); len(fields) > 0 && isFlag(fields[0]) {
		name = strings.TrimSpace(strings.TrimPrefix(name, fields[0]))
	}
	for _, marker := range []string{" VPN", " |"} {
		if before, _, found := strings.Cut(name, marker); found {
			name = strings.TrimSpace(before)
		}
	}
	flag := ""
	if fields := strings.Fields(fragment); len(fields) > 0 && isFlag(fields[0]) {
		flag = fields[0]
	}
	if flag == "" && info != nil {
		flag = CountryCodeToFlag(info.CountryCode)
	}
	isp := "Unknown"
	if info != nil && info.ISP != "" {
		isp = info.ISP
	}
	return fmt.Sprintf("%s %s (%s)", flag, name, isp)
}

func isAutoRoute(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "автовыбор") || strings.Contains(name, "auto select") || strings.Contains(name, "auto-select")
}

func isFlag(value string) bool {
	runes := []rune(value)
	return len(runes) == 2 && runes[0] >= 0x1F1E6 && runes[0] <= 0x1F1FF && runes[1] >= 0x1F1E6 && runes[1] <= 0x1F1FF
}

func credentialGatewayKey(record parse.ProxyRecord) string {
	keys := make([]string, 0, len(record.QueryParams))
	for key := range record.QueryParams {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{string(record.Protocol), strings.ToLower(strings.Trim(record.Host, "[]")), strconv.Itoa(record.Port)}
	for _, key := range keys {
		parts = append(parts, key+"="+record.QueryParams[key])
	}
	return strings.Join(parts, "\x00")
}

func buildName(geoInfo *geo.GeoInfo) string {
	city := geoInfo.City
	if city == "" {
		city = geoInfo.CountryCode
	}
	isp := geoInfo.ISP
	if isp == "" {
		isp = "Unknown"
	}
	return fmt.Sprintf("%s %s (%s)", CountryCodeToFlag(geoInfo.CountryCode), city, isp)
}
