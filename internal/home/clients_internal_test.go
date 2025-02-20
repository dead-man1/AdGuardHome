package home

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClientsContainer is a helper that creates a new clients container for
// tests.
func newClientsContainer(t *testing.T) (c *clientsContainer) {
	t.Helper()

	c = &clientsContainer{
		testing: true,
	}

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	err := c.Init(
		ctx,
		slogutil.NewDiscardLogger(),
		nil,
		client.EmptyDHCP{},
		nil,
		nil,
		&filtering.Config{},
	)

	require.NoError(t, err)

	return c
}

// TODO(s.chzhen): !! Move to client package.
func TestClientsCustomUpstream(t *testing.T) {
	clients := newClientsContainer(t)
	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Add client with upstreams.
	err := clients.storage.Add(ctx, &client.Persistent{
		Name: "client1",
		UID:  client.MustNewUID(),
		IPs:  []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1:2:3::4")},
		Upstreams: []string{
			"1.1.1.1",
			"[/example.org/]8.8.8.8",
		},
	})
	require.NoError(t, err)

	clients.storage.UpdateCommonUpstreamConfig(&client.CommonUpstreamConfig{})

	upsConf := clients.storage.CustomUpstreamConfig("", netip.MustParseAddr("1.2.3.4"))
	assert.Nil(t, upsConf)

	upsConf = clients.storage.CustomUpstreamConfig("", netip.MustParseAddr("1.1.1.1"))
	require.NotNil(t, upsConf)
}
