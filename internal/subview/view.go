package subview

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/rename"
)

type Format string

type Client string

const (
	FormatURL     Format = "url"
	FormatJSON    Format = "json"
	FormatSingbox Format = "singbox"

	ClientUnknown Client = "unknown"
	ClientV2rayNG Client = "v2rayng"
	ClientINCY    Client = "incy"
	ClientExclave Client = "exclave"
	ClientHusi    Client = "husi"
)

type Options struct {
	Format  Format
	Warp    bool
	Profile format.RoutingProfile
	Exclude map[string]struct{}
}

type Response struct {
	Body       []byte
	Filtered   int
	Unknown    int
	Conflict   int
	EntryCount int
}

func Parse(values url.Values) (Options, error) {
	return ParseForClient(values, ClientUnknown)
}

// ParseForClient selects a safe default for known Android subscription parsers.
// v2rayNG and INCY preserve full Xray configs; Exclave and Husi flatten their
// outbounds and therefore cannot preserve the proxy -> WARP chain.
func ParseForClient(values url.Values, client Client) (Options, error) {
	options := Options{Format: FormatURL, Profile: format.RoutingProfileRussia}
	if value := values.Get("format"); value != "" {
		options.Format = Format(value)
	}
	if options.Format != FormatURL && options.Format != FormatJSON && options.Format != FormatSingbox {
		return Options{}, fmt.Errorf("unsupported format %q", options.Format)
	}

	options.Warp = options.Format == FormatJSON || options.Format == FormatSingbox
	// Flattening clients break the Xray proxy -> WARP chain. sing-box keeps it
	// via outbound detour, so only the Xray JSON format needs the exception.
	if options.Format != FormatSingbox && (client == ClientExclave || client == ClientHusi) {
		options.Warp = false
	}
	if value := values.Get("warp"); value != "" {
		switch value {
		case "on":
			if client == ClientExclave || client == ClientHusi {
				return Options{}, fmt.Errorf("warp=on is unsupported by %s subscription import", client)
			}
			options.Warp = true
		case "off":
			options.Warp = false
		default:
			return Options{}, fmt.Errorf("unsupported warp mode %q", value)
		}
	}
	if options.Warp && options.Format == FormatURL {
		return Options{}, fmt.Errorf("warp=on requires format=json")
	}
	if value := values.Get("profile"); value != "" {
		switch value {
		case string(format.RoutingProfileRussia):
			options.Profile = format.RoutingProfileRussia
		case string(format.RoutingProfileNone):
			options.Profile = format.RoutingProfileNone
		default:
			return Options{}, fmt.Errorf("unsupported profile %q", value)
		}
		if options.Format == FormatURL {
			return Options{}, fmt.Errorf("profile=%s requires format=json", value)
		}
	}

	excluded, err := country.ParseCodes(values["exclude"])
	if err != nil {
		return Options{}, err
	}
	options.Exclude = excluded
	return options, nil
}

func DetectClient(userAgent, xClient string) Client {
	if strings.EqualFold(strings.TrimSpace(xClient), "INCY") {
		return ClientINCY
	}
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case strings.HasPrefix(userAgent, "v2rayng/"):
		return ClientV2rayNG
	case strings.HasPrefix(userAgent, "incy/"):
		return ClientINCY
	case strings.HasPrefix(userAgent, "exclave/"):
		return ClientExclave
	case strings.HasPrefix(userAgent, "husi/"):
		return ClientHusi
	default:
		return ClientUnknown
	}
}

func Render(data *pipeline.CachedData, options Options) Response {
	if len(options.Exclude) == 0 && (options.Profile == "" || options.Profile == format.RoutingProfileRussia) {
		if options.Format == FormatURL && !options.Warp && data.Output != "" {
			return Response{Body: []byte(data.Output), EntryCount: len(data.Entries)}
		}
	}
	entries := make([]rename.RenamedEntry, 0, len(data.Entries))
	response := Response{}
	for _, cached := range data.Entries {
		if options.Warp && !cached.WarpHealthy || !options.Warp && !cached.DirectHealthy {
			continue
		}
		decision := country.Filter(cached.Countries, options.Warp, options.Exclude)
		response.Unknown += decision.Unknown
		response.Conflict += decision.Conflict
		if !decision.Include {
			response.Filtered++
			continue
		}
		entry := cached.Entry
		if options.Warp && cached.WarpEntry.Record.Protocol != "" {
			entry = cached.WarpEntry
		}
		entries = append(entries, entry)
	}
	response.EntryCount = len(entries)
	meta := data.Metadata
	meta.TotalAlive = len(entries)
	switch options.Format {
	case FormatJSON:
		response.Body = format.FormatXrayJSONWithOptions(entries, meta, format.XrayJSONOptions{Warp: options.Warp, Profile: options.Profile})
		return response
	case FormatSingbox:
		response.Body = format.FormatSingboxJSONWithOptions(entries, meta, format.SingboxOptions{Warp: options.Warp, Profile: options.Profile})
		return response
	}
	response.Body = []byte(format.FormatOutput(entries, meta))
	return response
}
