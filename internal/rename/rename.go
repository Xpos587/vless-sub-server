package rename

import (
	"fmt"

	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/probe"
)

type RenamedEntry struct {
	Record         parse.ProxyRecord
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
}, probeResults map[string]*probe.ProbeResult) []RenamedEntry {
	var entries []RenamedEntry
	nameCounts := map[string]int{}

	for _, r := range records {
		key := fmt.Sprintf("%s:%d", r.Record.Host, r.Record.Port)
		p, ok := probeResults[key]
		if !ok || !p.Reachable {
			continue
		}

		baseName := buildName(r.Record, r.Geo, r.IsLAN)
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

func buildName(record parse.ProxyRecord, geoInfo *geo.GeoInfo, isLAN bool) string {
	if isLAN {
		return fmt.Sprintf("%s LAN %s", CountryCodeToFlag("LAN"), record.Host)
	}
	if geoInfo == nil {
		if record.Fragment != "" {
			return record.Fragment
		}
		return record.Host
	}

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