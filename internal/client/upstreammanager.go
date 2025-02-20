package client

import (
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
)

// CommonUpstreamConfig contains common settings for custom client upstream
// configurations.
type CommonUpstreamConfig struct {
	Bootstrap               upstream.Resolver
	UpstreamTimeout         time.Duration
	BootstrapPreferIPv6     bool
	EDNSClientSubnetEnabled bool
	UseHTTP3Upstreams       bool
}

// customUpstreamConfig contains custom client upstream configuration and the
// timestamp of the latest configuration update.
type customUpstreamConfig struct {
	prxConf    *proxy.CustomUpstreamConfig
	confUpdate time.Time
}

// upstreamManager stores and updates custom client upstream configurations.
type upstreamManager struct {
	// uidToCustomConf maps persistent client UID to the custom client upstream
	// configuration.
	uidToCustomConf map[UID]*customUpstreamConfig

	// commonConf is the common upstream configuration.
	commonConf *CommonUpstreamConfig

	// confUpdate is the timestamp of the latest common upstream configuration
	// update.
	confUpdate time.Time
}

// newUpstreamManager returns the new properly initialized upstream manager.
func newUpstreamManager() (m *upstreamManager) {
	return &upstreamManager{
		uidToCustomConf: make(map[UID]*customUpstreamConfig),
	}
}

// updateCommonUpstreamConfig updates the common upstream configuration and the
// timestamp of the latest configuration update.
func (m *upstreamManager) updateCommonUpstreamConfig(conf *CommonUpstreamConfig) {
	m.commonConf = conf
	m.confUpdate = time.Now()
}

// customUpstreamConfig returns the custom client upstream configuration.
func (m *upstreamManager) customUpstreamConfig(
	c *Persistent,
) (prxConf *proxy.CustomUpstreamConfig) {
	cliConf, ok := m.uidToCustomConf[c.UID]
	if ok && m.confUpdate.Equal(cliConf.confUpdate) {
		return cliConf.prxConf
	}

	prxConf = newCustomUpstreamConfig(c, m.commonConf)
	m.uidToCustomConf[c.UID] = &customUpstreamConfig{
		prxConf:    prxConf,
		confUpdate: m.confUpdate,
	}

	return prxConf
}

// clearUpstreamCache clears the upstream cache for each stored custom client
// upstream configuration.
func (m *upstreamManager) clearUpstreamCache() {
	for _, c := range m.uidToCustomConf {
		c.prxConf.ClearCache()
	}
}

// remove deletes the custom client upstream configuration.
func (m *upstreamManager) remove(c *Persistent) (err error) {
	cliConf, ok := m.uidToCustomConf[c.UID]
	if ok {
		return cliConf.prxConf.Close()
	}

	delete(m.uidToCustomConf, c.UID)

	return nil
}

// close shuts down each stored custom client upstream configuration.
func (m *upstreamManager) close() (err error) {
	var errs []error
	for _, c := range m.uidToCustomConf {
		errs = append(errs, c.prxConf.Close())
	}

	return errors.Join(errs...)
}

// newCustomUpstreamConfig returns the new properly initialized custom proxy
// upstream configuration for the client.
func newCustomUpstreamConfig(
	c *Persistent,
	conf *CommonUpstreamConfig,
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
