package exitprobe

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
)

func TestStartFetchGatewayBuildsAndStops(t *testing.T) {
	records := parse.ParseAllLines([]string{
		"vless://bec32c20-03e9-4235-9976-fcfbb5d3dc59@de.example.com:2083?flow=xtls-rprx-vision&fp=firefox&pbk=a3_DLO6p_ZfPf7I0JFTVlAI2pPAPtC-ji2diyPcHcQA&security=reality&sid=b4&sni=www.booking.com&type=tcp#de",
	}).Records
	if len(records) != 1 {
		t.Fatal("fixture did not parse")
	}

	gw, err := StartFetchGateway(records)
	if err != nil {
		t.Fatalf("StartFetchGateway: %v", err)
	}
	defer gw.Close()

	tags := gw.Tags()
	if len(tags) != 1 {
		t.Fatalf("tags = %v", tags)
	}
	if gw.DialContext(tags[0]) == nil {
		t.Fatal("DialContext returned nil")
	}
}

func TestStartFetchGatewayRejectsEmpty(t *testing.T) {
	if _, err := StartFetchGateway(nil); err == nil {
		t.Fatal("expected error for empty records")
	}
}
