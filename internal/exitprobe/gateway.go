package exitprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/michael/vless-sub-server/internal/parse"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// FetchGateway is a slim embedded xray instance whose outbounds are healthy
// pool proxies. It exists so the fetch stage can reach subscription sources
// that geo-block or otherwise refuse the server's direct egress — an
// anti-censorship aggregator should be able to use its own pool.
type FetchGateway struct {
	instance *core.Instance
	tags     []string
	ownsCore bool
}

func StartFetchGateway(records []parse.ProxyRecord) (*FetchGateway, error) {
	return StartFetchGatewayContext(context.Background(), records)
}

func StartFetchGatewayContext(ctx context.Context, records []parse.ProxyRecord) (*FetchGateway, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no gateway records")
	}

	if err := acquireEmbeddedXray(ctx); err != nil {
		return nil, fmt.Errorf("wait for embedded xray: %w", err)
	}
	started := false
	defer func() {
		if !started {
			releaseEmbeddedXray()
		}
	}()

	cfg := xrayDialConfig{Log: map[string]any{"loglevel": "error"}}
	tags := make([]string, len(records))
	for i, rec := range records {
		tags[i] = fmt.Sprintf("gateway_%d_out", i)
		cfg.Outbounds = append(cfg.Outbounds, buildOutbound(rec, tags[i]))
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode gateway config: %w", err)
	}
	xrayConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		return nil, fmt.Errorf("decode gateway config: %w", err)
	}
	coreConfig, err := xrayConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build gateway config: %w", err)
	}
	instance, err := core.New(coreConfig)
	if err != nil {
		return nil, fmt.Errorf("create gateway instance: %w", err)
	}
	if err := instance.Start(); err != nil {
		return nil, fmt.Errorf("start gateway instance: %w", err)
	}
	started = true
	return &FetchGateway{instance: instance, tags: tags, ownsCore: true}, nil
}

func (g *FetchGateway) Tags() []string {
	return append([]string(nil), g.tags...)
}

// DialContext returns a net/http-compatible dialer that forces connections
// through the given gateway outbound tag.
func (g *FetchGateway) DialContext(tag string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx = session.SetForcedOutboundTagToContext(ctx, tag)
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, g.instance, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	}
}

func (g *FetchGateway) Close() {
	if g.instance != nil {
		g.instance.Close()
		g.instance = nil
	}
	if g.ownsCore {
		g.ownsCore = false
		releaseEmbeddedXray()
	}
}
