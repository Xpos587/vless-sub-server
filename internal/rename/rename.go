package rename

import (
	"crypto/sha256"
	"fmt"
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
	baseNames := make([]string, len(records))
	exitIPs := make(map[string]map[string]struct{}, len(records))
	for i, r := range records {
		baseName := buildName(r.Geo)
		baseNames[i] = baseName
		if r.Geo == nil || r.Geo.IP == "" {
			continue
		}
		if exitIPs[baseName] == nil {
			exitIPs[baseName] = make(map[string]struct{})
		}
		exitIPs[baseName][r.Geo.IP] = struct{}{}
	}

	for i, r := range records {
		baseName := baseNames[i]
		if r.Geo != nil && r.Geo.IP != "" && len(exitIPs[baseName]) > 1 {
			baseName = fmt.Sprintf("%s · %s", baseName, exitID(r.Geo.IP))
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

// exitID distinguishes routes that share a city and provider without exposing
// their observable egress IP in a subscription name.
func exitID(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return fmt.Sprintf("%x", sum[:3])
}

func buildName(geoInfo *geo.GeoInfo) string {
	if geoInfo == nil {
		return "🌐 Unknown (Unknown)"
	}
	city := geoInfo.City
	if city == "" {
		city = "Unknown"
	}
	isp := geoInfo.ISP
	if isp == "" {
		isp = "Unknown"
	}
	flag := "🌐"
	if len(geoInfo.CountryCode) == 2 {
		flag = CountryCodeToFlag(strings.ToUpper(geoInfo.CountryCode))
	}
	return fmt.Sprintf("%s %s (%s)", flag, city, isp)
}
