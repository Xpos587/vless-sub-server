package rename

import (
	"fmt"

	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
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
}) []RenamedEntry {
	var entries []RenamedEntry
	nameCounts := map[string]int{}

	for _, r := range records {
		var baseName string
		if r.Geo != nil {
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