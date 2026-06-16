package geo

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

// ipwho.is response
type IPWhoisResponse struct {
	Success      bool              `json:"success"`
	IP           string            `json:"ip"`
	CountryCode  string            `json:"country_code"`
	Country      string            `json:"country"`
	Region       string            `json:"region"`
	City         string            `json:"city"`
	Connection   IPWhoisConnection `json:"connection"`
}

type IPWhoisConnection struct {
	ISP string `json:"isp"`
	Org string `json:"org"`
	ASN int    `json:"asn"`
}

// ip-api.com response (legacy)
type IPAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	Query       string `json:"query"`
}

