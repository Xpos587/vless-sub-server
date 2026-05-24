package parse

type Protocol string

const (
	VLESS  Protocol = "vless"
	VMess  Protocol = "vmess"
	Trojan Protocol = "trojan"
	SS     Protocol = "ss"
)

type ProxyRecord struct {
	Protocol       Protocol
	Host           string
	Port           int
	UUIDOrPassword string
	QueryParams    map[string]string
	Fragment       string
	OriginalLine   string
}
