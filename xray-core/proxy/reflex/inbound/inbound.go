// Package inbound implements the Reflex inbound handler.
// This is a stub; replace with full implementation per step docs.
package inbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

// Handler is the Reflex inbound handler (stub until implemented).
type Handler struct{}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.Process(). Stub: does nothing.
func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	_ = ctx
	_ = network
	_ = conn
	_ = dispatcher
	return nil
}

// New creates a new Reflex inbound handler from config.
func New(ctx context.Context, config *reflex.InboundConfig) (proxy.InboundHandler, error) {
	_ = ctx
	_ = config
	return &Handler{}, nil
}
