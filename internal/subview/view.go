package subview

import (
	"fmt"
	"net/url"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/rename"
)

type Format string

const (
	FormatURL  Format = "url"
	FormatJSON Format = "json"
)

type Options struct {
	Format  Format
	Warp    bool
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
	options := Options{Format: FormatURL}
	if value := values.Get("format"); value != "" {
		options.Format = Format(value)
	}
	if options.Format != FormatURL && options.Format != FormatJSON {
		return Options{}, fmt.Errorf("unsupported format %q", options.Format)
	}

	options.Warp = options.Format == FormatJSON
	if value := values.Get("warp"); value != "" {
		switch value {
		case "on":
			options.Warp = true
		case "off":
			options.Warp = false
		default:
			return Options{}, fmt.Errorf("unsupported warp mode %q", value)
		}
	}
	if options.Warp && options.Format != FormatJSON {
		return Options{}, fmt.Errorf("warp=on requires format=json")
	}

	excluded, err := country.ParseCodes(values["exclude"])
	if err != nil {
		return Options{}, err
	}
	options.Exclude = excluded
	return options, nil
}

func Render(data *pipeline.CachedData, options Options) Response {
	if len(options.Exclude) == 0 {
		if options.Format == FormatURL && !options.Warp && data.Output != "" {
			return Response{Body: []byte(data.Output), EntryCount: len(data.Entries)}
		}
		if options.Format == FormatJSON && options.Warp && len(data.JSONOutput) > 0 {
			return Response{Body: append([]byte(nil), data.JSONOutput...), EntryCount: len(data.Entries)}
		}
	}
	entries := make([]rename.RenamedEntry, 0, len(data.Entries))
	response := Response{}
	for _, cached := range data.Entries {
		decision := country.Filter(cached.Countries, options.Warp, options.Exclude)
		response.Unknown += decision.Unknown
		response.Conflict += decision.Conflict
		if !decision.Include {
			response.Filtered++
			continue
		}
		entries = append(entries, cached.Entry)
	}
	response.EntryCount = len(entries)
	meta := data.Metadata
	meta.TotalAlive = len(entries)
	if options.Format == FormatJSON {
		response.Body = format.FormatXrayJSONWithOptions(entries, meta, format.XrayJSONOptions{Warp: options.Warp})
		return response
	}
	response.Body = []byte(format.FormatOutput(entries, meta))
	return response
}
