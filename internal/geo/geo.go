package geo

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

// ip-api.com response
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

