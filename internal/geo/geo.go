package geo

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

// api.ip.sb/geoip response
type IPSbResponse struct {
	IP           string  `json:"ip"`
	CountryCode  string  `json:"country_code"`
	Country      string  `json:"country"`
	City         string  `json:"city"`
	Region       string  `json:"region"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
	ASN          int     `json:"asn"`
	ASNOrg       string  `json:"asn_organization"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Timezone     string  `json:"timezone"`
}