package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/rename"
)

func TestWriteSubscriptionResponseRejectsWarpURL(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sub?warp=on", nil)
	writeSubscriptionResponse(recorder, request, handlerCache())
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestWriteSubscriptionResponseSetsCountryDiagnostics(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sub?format=json&warp=on&exclude=fi", nil)
	writeSubscriptionResponse(recorder, request, handlerCache())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	for name, want := range map[string]string{
		"X-Warp":             "on",
		"X-Profile":          "ru",
		"X-Country-Filtered": "1",
		"X-Country-Unknown":  "0",
		"X-Country-Conflict": "0",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if recorder.Body.String() != "[]" {
		t.Fatalf("body = %s", recorder.Body.String())
	}
}

func TestWriteSubscriptionResponsePreservesDefaultFastPath(t *testing.T) {
	data := handlerCache()
	for _, test := range []struct {
		url  string
		body string
	}{
		{url: "/sub", body: data.Output},
		{url: "/sub?format=json", body: string(data.JSONOutput)},
	} {
		recorder := httptest.NewRecorder()
		writeSubscriptionResponse(recorder, httptest.NewRequest(http.MethodGet, test.url, nil), data)
		if recorder.Body.String() != test.body {
			t.Fatalf("%s body changed: %q", test.url, recorder.Body.String())
		}
	}
}

func TestWriteSubscriptionResponseKeepsRootURLDirectForFullConfigClients(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"v2rayNG": {"User-Agent": "v2rayNG/2.2.6"},
		"INCY":    {"User-Agent": "INCY/3.0/Android", "X-Client": "INCY"},
	} {
		t.Run(name, func(t *testing.T) {
			data := handlerCache()
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/sub", nil)
			for key, value := range headers {
				request.Header.Set(key, value)
			}

			writeSubscriptionResponse(recorder, request, data)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
				t.Fatalf("content type = %q", got)
			}
			if got := recorder.Header().Get("X-Warp"); got != "off" {
				t.Fatalf("X-Warp = %q", got)
			}
			if recorder.Body.String() != data.Output {
				t.Fatalf("body = %s", recorder.Body.String())
			}
		})
	}
}

func TestWriteSubscriptionResponseDoesNotSendWarpChainToFlatteningClients(t *testing.T) {
	for name, userAgent := range map[string]string{
		"Exclave": "Exclave/0.17.46",
		"Husi":    "husi/1.4.3 (143; sing-box 1.12.0)",
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/sub?format=json", nil)
			request.Header.Set("User-Agent", userAgent)

			writeSubscriptionResponse(recorder, request, handlerCache())

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("X-Warp"); got != "off" {
				t.Fatalf("X-Warp = %q", got)
			}
			var configs []map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &configs); err != nil {
				t.Fatal(err)
			}
			for _, config := range configs {
				for _, raw := range config["outbounds"].([]any) {
					if raw.(map[string]any)["protocol"] == "wireguard" {
						t.Fatalf("flattening client received a WARP chain: %s", recorder.Body.String())
					}
				}
			}
		})
	}
}

func TestWriteSubscriptionResponseExplicitURLKeepsV2rayNGDirect(t *testing.T) {
	data := handlerCache()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sub?format=url", nil)
	request.Header.Set("User-Agent", "v2rayNG/2.2.6")

	writeSubscriptionResponse(recorder, request, data)

	if recorder.Body.String() != data.Output || recorder.Header().Get("X-Warp") != "off" {
		t.Fatalf("headers=%v body=%q", recorder.Header(), recorder.Body.String())
	}
}

func TestHandleExitObservationPrefersCloudflareClientAddress(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/_exit", nil)
	request.Header.Set("CF-Connecting-IP", "198.51.100.1")
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	handleExitObservation(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"ip":"198.51.100.1"}`+"\n" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestHandleExitObservationUsesOriginalForwardedClientAddress(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/_exit", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.1, 172.18.0.2")
	handleExitObservation(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"ip":"198.51.100.1"}`+"\n" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func handlerCache() *pipeline.CachedData {
	entry := rename.RenamedEntry{
		Record:          parse.ProxyRecord{Protocol: parse.VLESS, Host: "example.com", Port: 443, UUIDOrPassword: "uuid", QueryParams: map[string]string{"type": "tcp"}},
		RenamedFragment: "Example",
	}
	meta := format.FormatMetadata{TotalAlive: 1}
	return &pipeline.CachedData{
		Entries: []pipeline.CachedEntry{{
			Entry:         entry,
			DirectHealthy: true,
			WarpHealthy:   true,
			Countries: country.RouteCountries{
				DirectV4: country.FamilyResult{Available: true, Country: "AE", Status: country.Confirmed},
				WarpV4:   country.FamilyResult{Available: true, Country: "FI", Status: country.Confirmed},
			},
		}},
		Metadata:    meta,
		Output:      "precomputed-url",
		JSONOutput:  []byte(`[{"precomputed":true}]`),
		LastRefresh: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}
}
