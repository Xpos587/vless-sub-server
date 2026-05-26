package geo

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

// ipwho.is response
type IPWhoisResponse struct {
	IP          string `json:"ip"`
	Success     bool   `json:"success"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Connection  struct {
		ISP string `json:"isp"`
	} `json:"connection"`
}
