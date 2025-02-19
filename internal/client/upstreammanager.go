package client

import (
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/stringutil"
)

// TODO(s.chzhen): !! Improve documentation, naming.
type UpstreamConfig struct {
	Bootstrap                upstream.Resolver
	LatestUpstreamConfUpdate time.Time
	UpstreamTimeout          time.Duration
	BootstrapPreferIPv6      bool
	EDNSClientSubnetEnabled  bool
	UseHTTP3Upstreams        bool
}

type clientUpstreamConfig struct {
	// TODO(s.chzhen): !! Store a list of upstreams and cache settings instead.
	client  *Persistent
	prxConf *proxy.CustomUpstreamConfig
}

type upstreamManager struct {
	uidToClientConf map[UID]*clientUpstreamConfig
	conf            *UpstreamConfig
}

func newUpstreamManager() (m *upstreamManager) {
	return &upstreamManager{
		uidToClientConf: make(map[UID]*clientUpstreamConfig),
	}
}

func (m *upstreamManager) latestConfigUpdate() (t time.Time) {
	if m.conf == nil {
		return time.Time{}
	}

	return m.conf.LatestUpstreamConfUpdate
}

func (m *upstreamManager) updateConfig(conf *UpstreamConfig) {
	m.conf = conf

	for uid, c := range m.uidToClientConf {
		prxConf := newCustomUpstreamConfig(c.client, m.conf)
		m.uidToClientConf[uid] = &clientUpstreamConfig{
			client:  c.client,
			prxConf: prxConf,
		}
	}
}

func (m *upstreamManager) customUpstreamConfig(
	c *Persistent,
) (prxConf *proxy.CustomUpstreamConfig) {
	cliConf, ok := m.uidToClientConf[c.UID]
	if ok {
		return cliConf.prxConf
	}

	prxConf = newCustomUpstreamConfig(c, m.conf)
	m.uidToClientConf[c.UID] = &clientUpstreamConfig{
		client:  c,
		prxConf: prxConf,
	}

	return prxConf
}

// TODO(s.chzhen): !! Use it.
func (m *upstreamManager) clearCache() {
	for _, c := range m.uidToClientConf {
		c.prxConf.ClearCache()
	}
}

// TODO(s.chzhen): !! Use it.
func (m *upstreamManager) close() {
	for _, c := range m.uidToClientConf {
		c.prxConf.Close()
	}
}

// newCustomUpstreamConfig returns the new properly initialized custom proxy
// upstream configuration for the client.
func newCustomUpstreamConfig(
	c *Persistent,
	conf *UpstreamConfig,
) (prxConf *proxy.CustomUpstreamConfig) {
	upstreams := stringutil.FilterOut(c.Upstreams, aghnet.IsCommentOrEmpty)
	if len(upstreams) == 0 {
		return nil
	}

	upsConf, err := proxy.ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			Bootstrap:    conf.Bootstrap,
			Timeout:      time.Duration(conf.UpstreamTimeout),
			HTTPVersions: aghnet.UpstreamHTTPVersions(conf.UseHTTP3Upstreams),
			PreferIPv6:   conf.BootstrapPreferIPv6,
		},
	)
	if err != nil {
		// Should not happen because upstreams are already validated.  See
		// [Persistent.validate].
		panic(err)
	}

	return proxy.NewCustomUpstreamConfig(
		upsConf,
		c.UpstreamsCacheEnabled,
		int(c.UpstreamsCacheSize),
		conf.EDNSClientSubnetEnabled,
	)
}
