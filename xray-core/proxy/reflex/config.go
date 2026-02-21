// Package reflex provides the Reflex proxy protocol for Xray-Core.
// Config types match the step1 spec (config.proto). Students may replace
// with protobuf-generated types.
package reflex

// User represents a client (step1 spec).
type User struct {
	Id     string // UUID
	Policy string
}

// Account for protocol.Account (step1).
type Account struct {
	Id string
}

// Fallback config (step1).
type Fallback struct {
	Dest uint32
}

// InboundConfig is the inbound config (step1).
type InboundConfig struct {
	Clients  []*User
	Fallback *Fallback
}

// OutboundConfig (step1).
type OutboundConfig struct {
	Address string
	Port    uint32
	Id      string
}
