package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// ---- Inbound ----

type ReflexInboundClient struct {
	Id     string `json:"id"`
	Policy string `json:"policy"`
}

type ReflexFallbackConfig struct {
	Dest uint32 `json:"dest"`
}

type ReflexInboundConfig struct {
	Clients  []json.RawMessage     `json:"clients"`
	Fallback *ReflexFallbackConfig `json:"fallback"`
}

// Build implements Buildable
func (c *ReflexInboundConfig) Build() (proto.Message, error) {
	config := new(reflex.InboundConfig)

	for _, rawClient := range c.Clients {
		client := new(ReflexInboundClient)
		if err := json.Unmarshal(rawClient, client); err != nil {
			return nil, errors.New("Reflex clients: invalid client").Base(err)
		}
		u, err := uuid.ParseString(client.Id)
		if err != nil {
			return nil, errors.New("Reflex clients: invalid UUID").Base(err)
		}
		config.Clients = append(config.Clients, &reflex.User{
			Id:     u.String(),
			Policy: client.Policy,
		})
	}

	if c.Fallback != nil {
		config.Fallback = &reflex.Fallback{
			Dest: c.Fallback.Dest,
		}
	}

	return config, nil
}

// ---- Outbound ----

type ReflexOutboundConfig struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Id      string `json:"id"`
}

// Build implements Buildable
func (c *ReflexOutboundConfig) Build() (proto.Message, error) {
	if c.Address == "" {
		return nil, errors.New("Reflex outbound: \"address\" is not set")
	}
	u, err := uuid.ParseString(c.Id)
	if err != nil {
		return nil, errors.New("Reflex outbound: invalid UUID").Base(err)
	}

	config := &reflex.OutboundConfig{
		Address: c.Address,
		Port:    c.Port,
		Id:      u.String(),
	}

	return config, nil
}
