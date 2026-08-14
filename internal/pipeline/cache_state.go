package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCached restores the last atomically published subscription before a
// refresh starts, keeping the endpoint available during process restarts.
func (p *Pipeline) LoadCached(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var cached CachedData
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("decode cached subscription: %w", err)
	}
	if cached.Output == "" || len(cached.JSONOutput) == 0 || cached.LastRefresh.IsZero() {
		return fmt.Errorf("cached subscription is incomplete")
	}
	p.cache.Store(&cached)
	return nil
}

// SaveCached writes a complete snapshot through a same-directory temporary
// file, so a crash cannot replace the last known-good cache with partial JSON.
func (p *Pipeline) SaveCached(path string) error {
	if path == "" {
		return nil
	}
	cached, ok := p.Cached()
	if !ok {
		return nil
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("encode cached subscription: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".subscription-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
