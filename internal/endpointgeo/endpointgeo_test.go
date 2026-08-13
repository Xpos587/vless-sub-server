package endpointgeo

import "testing"

func TestParsePreservesEndpointMetadata(t *testing.T) {
	info, ok := parse([]byte(`{"success":true,"ip":"198.51.100.1","country_code":"pl","city":"Warsaw","connection":{"isp":"Example ISP","org":"Example Org"}}`))
	if !ok || info.CountryCode != "PL" || info.City != "Warsaw" || info.ISP != "Example ISP" || info.IP != "198.51.100.1" {
		t.Fatalf("info = %#v, ok = %t", info, ok)
	}
}
