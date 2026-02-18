package inbound

import (
	"context"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{
		Id: a.Id,
	}
}

type FallbackConfig struct {
	Dest uint32
}

func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Will be filled in Step 2 (handshake).
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(config.Clients)),
	}

	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email: client.Id,
			Account: &MemoryAccount{
				Id: client.Id,
			},
		})
	}

	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{
			Dest: config.Fallback.Dest,
		}
	}

	return handler, nil
}
