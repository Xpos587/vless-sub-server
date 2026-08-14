package rename

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
)

func TestRenameAllUsesObservedExitGeoForSharedCredentialGateway(t *testing.T) {
	shared := map[string]string{
		"type": "tcp", "security": "reality", "flow": "xtls-rprx-vision",
		"sni": "www.booking.com", "pbk": "shared-key", "sid": "shared-id",
	}
	records := []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}{
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "new-zealand", QueryParams: cloneParams(shared), Fragment: "🇳🇿 Новая Зеландия VPN - 1 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "malaysia", QueryParams: cloneParams(shared), Fragment: "🇲🇾 Малайзия VPN - 1 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "vietnam", QueryParams: cloneParams(shared), Fragment: "🇻🇳 Вьетнам VPN - 1 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
	}

	got := RenameAll(records)
	want := []string{
		"🇭🇰 Hong Kong (VolnaApp LLP)",
		"🇭🇰 Hong Kong (VolnaApp LLP) (2)",
		"🇭🇰 Hong Kong (VolnaApp LLP) (3)",
	}
	for i := range want {
		if got[i].RenamedFragment != want[i] {
			t.Fatalf("entry %d name = %q, want %q", i, got[i].RenamedFragment, want[i])
		}
	}
}

func TestRenameAllStillUsesObservedGeoForIndependentServers(t *testing.T) {
	records := []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}{
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "one.example", Port: 443, UUIDOrPassword: "one", Fragment: "Original One"}, Geo: &geo.GeoInfo{CountryCode: "DE", City: "Frankfurt", ISP: "Example"}},
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "two.example", Port: 443, UUIDOrPassword: "two", Fragment: "Original Two"}, Geo: &geo.GeoInfo{CountryCode: "NL", City: "Amsterdam", ISP: "Example"}},
	}

	got := RenameAll(records)
	if got[0].RenamedFragment != "🇩🇪 Frankfurt (Example)" || got[1].RenamedFragment != "🇳🇱 Amsterdam (Example)" {
		t.Fatalf("names = %#v", got)
	}
}

func TestRenameAllUsesObservedGeoForStandaloneAutoRoute(t *testing.T) {
	records := []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}{
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "auto", Fragment: "🇪🇺 АВТОВЫБОР - VPN 10 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
	}

	got := RenameAll(records)
	if got[0].RenamedFragment != "🇭🇰 Hong Kong (VolnaApp LLP)" {
		t.Fatalf("name = %q", got[0].RenamedFragment)
	}
}

func TestRenameAllUsesObservedExitGeoForAutoRouteInSharedGateway(t *testing.T) {
	shared := map[string]string{"type": "tcp", "security": "reality", "flow": "xtls-rprx-vision", "sni": "www.booking.com", "pbk": "shared-key", "sid": "shared-id"}
	records := []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}{
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "auto", QueryParams: cloneParams(shared), Fragment: "🇪🇺 АВТОВЫБОР - VPN 10 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
		{Record: parse.ProxyRecord{Protocol: parse.VLESS, Host: "170.168.90.1", Port: 2083, UUIDOrPassword: "region", QueryParams: cloneParams(shared), Fragment: "🇻🇳 Вьетнам VPN - 1 Гбит ⚡"}, Geo: &geo.GeoInfo{CountryCode: "HK", City: "Hong Kong", ISP: "VolnaApp LLP"}},
	}

	got := RenameAll(records)
	if got[0].RenamedFragment != "🇭🇰 Hong Kong (VolnaApp LLP)" {
		t.Fatalf("auto name = %q", got[0].RenamedFragment)
	}
}

func TestRenameAllUsesStandardUnknownFallback(t *testing.T) {
	got := RenameAll([]struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}{{Record: parse.ProxyRecord{Host: "unknown.example", Fragment: "🇷🇺 Русское upstream имя"}}})
	if got[0].RenamedFragment != "🌐 Unknown (Unknown)" {
		t.Fatalf("name = %q", got[0].RenamedFragment)
	}
}

func cloneParams(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
