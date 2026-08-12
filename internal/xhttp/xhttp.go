package xhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

var explicitKeys = map[string]struct{}{
	"host":  {},
	"path":  {},
	"mode":  {},
	"extra": {},
}

// SettingsFromParams reconstructs xray-core xhttpSettings from share-link
// parameters. Xray applies host/path/mode over the low-frequency JSON in extra.
func SettingsFromParams(params map[string]string) (map[string]any, error) {
	settings := make(map[string]any)
	for _, key := range []string{"host", "path", "mode"} {
		if value := params[key]; value != "" {
			settings[key] = value
		}
	}
	if raw := params["extra"]; raw != "" {
		normalized, err := NormalizeExtra(raw)
		if err != nil {
			return nil, err
		}
		settings["extra"] = normalized
	}
	return settings, nil
}

// ParamsFromSettings converts complete xhttpSettings to the official share-link
// shape: host/path/mode stay editable and every other field is carried in extra.
func ParamsFromSettings(settings map[string]any) (map[string]string, error) {
	params := make(map[string]string)
	for _, key := range []string{"host", "path", "mode"} {
		if value, ok := settings[key].(string); ok && value != "" {
			params[key] = value
		}
	}

	extra := make(map[string]any)
	if value, ok := settings["extra"]; ok && value != nil {
		decoded, err := decodeObject(value)
		if err != nil {
			return nil, fmt.Errorf("invalid xHTTP extra: %w", err)
		}
		for key, item := range decoded {
			extra[key] = item
		}
	}
	for key, value := range settings {
		if _, explicit := explicitKeys[key]; explicit || value == nil {
			continue
		}
		extra[key] = value
	}
	if len(extra) > 0 {
		data, err := json.Marshal(extra)
		if err != nil {
			return nil, fmt.Errorf("encode xHTTP extra: %w", err)
		}
		params["extra"] = string(data)
	}
	return params, nil
}

func NormalizeExtra(raw string) (json.RawMessage, error) {
	value, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid xHTTP extra: %w", err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode xHTTP extra: %w", err)
	}
	return json.RawMessage(data), nil
}

func decodeObject(value any) (map[string]any, error) {
	var data []byte
	switch typed := value.(type) {
	case string:
		data = []byte(strings.TrimSpace(typed))
	case json.RawMessage:
		data = bytes.TrimSpace(typed)
	case []byte:
		data = bytes.TrimSpace(typed)
	case map[string]any:
		data, _ = json.Marshal(typed)
	default:
		var err error
		data, err = json.Marshal(typed)
		if err != nil {
			return nil, err
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty object")
	}

	// Some producers serialize extra as a JSON string containing the object.
	if data[0] == '"' {
		var nested string
		if err := json.Unmarshal(data, &nested); err != nil {
			return nil, err
		}
		data = []byte(strings.TrimSpace(nested))
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("extra must be a JSON object")
	}
	return object, nil
}
