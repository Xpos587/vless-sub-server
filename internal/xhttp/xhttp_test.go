package xhttp

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSettingsFromParamsPreservesCompleteExtra(t *testing.T) {
	extra := `{"headers":{"User-Agent":"Mozilla/5.0"},"xPaddingBytes":"100-1000","noGRPCHeader":true,"scMaxEachPostBytes":"500000-1000000","xmux":{"maxConcurrency":"2-4","hMaxRequestTimes":"600-900"},"downloadSettings":{"address":"download.example.com","port":443,"network":"xhttp","security":"tls","xhttpSettings":{"path":"/down"}},"futureOption":{"enabled":true}}`
	settings, err := SettingsFromParams(map[string]string{
		"type":  "xhttp",
		"host":  "cdn.example.com",
		"path":  "/explicit",
		"mode":  "packet-up",
		"extra": extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings["host"] != "cdn.example.com" || settings["path"] != "/explicit" || settings["mode"] != "packet-up" {
		t.Fatalf("explicit settings lost: %#v", settings)
	}
	gotExtra, ok := settings["extra"].(json.RawMessage)
	if !ok {
		t.Fatalf("extra type = %T", settings["extra"])
	}
	assertJSONEqual(t, gotExtra, []byte(extra))
}

func TestParamsFromSettingsFoldsAllLowFrequencyFieldsIntoExtra(t *testing.T) {
	settings := map[string]any{
		"host":               "cdn.example.com",
		"path":               "/xhttp",
		"mode":               "stream-up",
		"headers":            map[string]any{"User-Agent": "Mozilla/5.0"},
		"scMaxEachPostBytes": "500000-1000000",
		"xmux":               map[string]any{"maxConcurrency": float64(4)},
		"futureOption":       map[string]any{"enabled": true},
	}
	params, err := ParamsFromSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if params["host"] != "cdn.example.com" || params["path"] != "/xhttp" || params["mode"] != "stream-up" {
		t.Fatalf("explicit params lost: %#v", params)
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(params["extra"]), &extra); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"headers", "scMaxEachPostBytes", "xmux", "futureOption"} {
		if _, ok := extra[key]; !ok {
			t.Fatalf("%s missing from extra %#v", key, extra)
		}
	}
}

func TestParamsFromSettingsMergesNestedExtraWithDirectFields(t *testing.T) {
	settings := map[string]any{
		"path":    "/xhttp",
		"extra":   map[string]any{"xmux": map[string]any{"maxConcurrency": float64(2)}, "noSSEHeader": true},
		"headers": map[string]any{"Accept-Language": "en-US"},
	}
	params, err := ParamsFromSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(params["extra"]), &extra); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"xmux", "noSSEHeader", "headers"} {
		if _, ok := extra[key]; !ok {
			t.Fatalf("merged extra lost %s: %#v", key, extra)
		}
	}
}

func TestNormalizeExtraRejectsNonObject(t *testing.T) {
	for _, raw := range []string{``, `null`, `[]`, `"text"`, `{broken`} {
		if _, err := NormalizeExtra(raw); err == nil {
			t.Fatalf("NormalizeExtra(%q) succeeded", raw)
		}
	}
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("got JSON: %v", err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("want JSON: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON mismatch\ngot:  %s\nwant: %s", got, want)
	}
}
