// Package outbound implements the Reflex outbound handler (stub).
package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

// Handler is the Reflex outbound handler (stub).
type Handler struct{}

// Process implements proxy.Outbound.Process(). Stub: returns nil.
func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
	_ = ctx
	_ = link
	_ = d
	return nil
}

// New creates a new Reflex outbound handler.
func New(ctx context.Context, config *reflex.OutboundConfig) (proxy.OutboundHandler, error) {
	_ = ctx
	_ = config
	return &Handler{}, nil
}
