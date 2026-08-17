package pipeline

import (
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/parse"
)

// SourceAttribution is the per-subscription breakdown of one refresh cycle.
type SourceAttribution struct {
	URL        string
	FetchOK    bool
	Stale      bool
	Lines      int
	Parsed     int
	Skipped    int
	Duplicates int
	Unique     int
}

// AttributeSources parses every merged source independently and attributes
// each unique record to its first contributing source, mirroring the global
// dedup that ParseAllLines performs on the flattened line list.
func AttributeSources(merged []fetch.MergedSource) ([]SourceAttribution, map[string]int) {
	sources := make([]SourceAttribution, len(merged))
	owners := map[string]int{}
	seen := map[string]bool{}

	for i, src := range merged {
		attr := SourceAttribution{URL: src.URL, FetchOK: src.FetchOK, Stale: src.Stale, Lines: len(src.Lines)}
		result := parse.ParseAllLines(src.Lines)
		attr.Parsed = len(result.Records)
		attr.Skipped = result.Skipped
		attr.Duplicates = result.Duplicates
		for _, record := range result.Records {
			key := parse.DedupKey(record)
			if seen[key] {
				attr.Duplicates++
				continue
			}
			seen[key] = true
			owners[identity(record)] = i
			attr.Unique++
		}
		sources[i] = attr
	}
	return sources, owners
}
