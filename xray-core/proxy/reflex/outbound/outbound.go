package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	server *protocol.ServerSpec
	pm     policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	dest := net.TCPDestination(net.DomainAddress(config.Address), net.Port(config.Port))

	user := &protocol.MemoryUser{
		Email: "",
		// For Reflex we don’t use account here yet.
	}

	spec := &protocol.ServerSpec{
		Destination: dest,
		User:        user,
	}

	v := core.MustFromContext(ctx)

	return &Handler{
		server: spec,
		pm:     v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	dest := h.server.Destination
	conn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return errors.New("reflex: failed to dial destination ").Base(err)
	}
	defer conn.Close()

	// Simple TCP pipe.
	inboundReader := link.Reader
	inboundWriter := link.Writer

	serverReader := buf.NewReader(conn)
	serverWriter := buf.NewWriter(conn)

	// Uplink: client → server
	uplinkDone := make(chan error, 1)
	go func() {
		uplinkDone <- buf.Copy(inboundReader, serverWriter, nil)
		common.Interrupt(serverWriter)
	}()

	// Downlink: server → client
	downlinkErr := buf.Copy(serverReader, inboundWriter, nil)
	common.Interrupt(serverReader)

	uplinkErr := <-uplinkDone
	if downlinkErr != nil {
		return downlinkErr
	}
	return uplinkErr
}
