package reflex

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"sort"
	"sync"
	"time"
)

// PacketSizeDist represents a weighted packet size in a traffic profile.
type PacketSizeDist struct {
	Size   int
	Weight float64
}

// DelayDist represents a weighted inter-packet delay in a traffic profile.
type DelayDist struct {
	Delay  time.Duration
	Weight float64
}

// TrafficProfile describes the statistical properties of a target protocol's
// traffic (packet size distribution and inter-packet timing). The proxy
// morphs its own traffic to match these distributions, making it harder
// for an observer to distinguish proxy traffic from the target protocol.
type TrafficProfile struct {
	Name        string
	PacketSizes []PacketSizeDist
	Delays      []DelayDist

	nextPacketSize int
	nextDelay      time.Duration
	mu             sync.Mutex
}

// GetPacketSize returns a packet size sampled from the profile's distribution.
// If SetNextPacketSize was called, the override value is returned once.
func (p *TrafficProfile) GetPacketSize() int {
	p.mu.Lock()
	if p.nextPacketSize > 0 {
		size := p.nextPacketSize
		p.nextPacketSize = 0
		p.mu.Unlock()
		return size
	}
	p.mu.Unlock()

	return sampleSize(p.PacketSizes)
}

// GetDelay returns an inter-packet delay sampled from the profile's distribution.
// If SetNextDelay was called, the override value is returned once.
func (p *TrafficProfile) GetDelay() time.Duration {
	p.mu.Lock()
	if p.nextDelay > 0 {
		delay := p.nextDelay
		p.nextDelay = 0
		p.mu.Unlock()
		return delay
	}
	p.mu.Unlock()

	return sampleDelay(p.Delays)
}

// SetNextPacketSize overrides the next call to GetPacketSize.
// Used when handling PADDING_CTRL frames from the peer.
func (p *TrafficProfile) SetNextPacketSize(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextPacketSize = size
}

// SetNextDelay overrides the next call to GetDelay.
// Used when handling TIMING_CTRL frames from the peer.
func (p *TrafficProfile) SetNextDelay(delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextDelay = delay
}

func sampleSize(dist []PacketSizeDist) int {
	if len(dist) == 0 {
		return 512
	}
	r := mrand.Float64()
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Size
		}
	}
	return dist[len(dist)-1].Size
}

func sampleDelay(dist []DelayDist) time.Duration {
	if len(dist) == 0 {
		return 10 * time.Millisecond
	}
	r := mrand.Float64()
	cumsum := 0.0
	for _, d := range dist {
		cumsum += d.Weight
		if r <= cumsum {
			return d.Delay
		}
	}
	return dist[len(dist)-1].Delay
}

// ---- Built-in profiles ----
//
// YouTube profile: modeled after TCP video streaming traffic.
// Sources: Rao et al. "Network Characteristics of Video Streaming Traffic"
// (IEEE INFOCOM 2011); empirical observations of DASH/HLS delivery.
// Most video segments are transmitted at or near MTU in bursts, with
// smaller packets for manifest/control data.
//
// Zoom profile: modeled after real-time video conferencing traffic.
// Sources: Xu et al. "An Analysis of Real-Time Video Communication Traffic"
// (IMC 2022); empirical observations of RTP media delivery.
// Combines small audio frames (~160-200 B, 20 ms) with larger video
// frames (~400-1200 B, 30-50 ms intervals).

var Profiles = map[string]*TrafficProfile{
	"youtube": {
		Name: "YouTube Streaming",
		PacketSizes: []PacketSizeDist{
			{Size: 1400, Weight: 0.35},
			{Size: 1200, Weight: 0.25},
			{Size: 1000, Weight: 0.15},
			{Size: 800, Weight: 0.10},
			{Size: 600, Weight: 0.08},
			{Size: 400, Weight: 0.05},
			{Size: 200, Weight: 0.02},
		},
		Delays: []DelayDist{
			{Delay: 5 * time.Millisecond, Weight: 0.25},
			{Delay: 10 * time.Millisecond, Weight: 0.30},
			{Delay: 15 * time.Millisecond, Weight: 0.20},
			{Delay: 20 * time.Millisecond, Weight: 0.15},
			{Delay: 30 * time.Millisecond, Weight: 0.07},
			{Delay: 50 * time.Millisecond, Weight: 0.03},
		},
	},
	"zoom": {
		Name: "Zoom Video Call",
		PacketSizes: []PacketSizeDist{
			{Size: 160, Weight: 0.15},
			{Size: 200, Weight: 0.10},
			{Size: 400, Weight: 0.10},
			{Size: 600, Weight: 0.20},
			{Size: 800, Weight: 0.20},
			{Size: 1000, Weight: 0.15},
			{Size: 1200, Weight: 0.10},
		},
		Delays: []DelayDist{
			{Delay: 10 * time.Millisecond, Weight: 0.15},
			{Delay: 20 * time.Millisecond, Weight: 0.30},
			{Delay: 30 * time.Millisecond, Weight: 0.25},
			{Delay: 40 * time.Millisecond, Weight: 0.15},
			{Delay: 50 * time.Millisecond, Weight: 0.10},
			{Delay: 60 * time.Millisecond, Weight: 0.05},
		},
	},
}

// LookupProfile returns the traffic profile for the given name, or nil.
func LookupProfile(name string) *TrafficProfile {
	return Profiles[name]
}

// ---- Padding helpers ----

// BuildMorphedPayload wraps data with a 2-byte length prefix and pads to
// targetSize using cryptographically random bytes.
// Format: [2 bytes originalLen][data][random padding]
func BuildMorphedPayload(data []byte, targetSize int) []byte {
	if targetSize < 3 {
		targetSize = 3
	}
	morphed := make([]byte, targetSize)
	binary.BigEndian.PutUint16(morphed[:2], uint16(len(data)))
	copy(morphed[2:], data)
	if padStart := 2 + len(data); padStart < targetSize {
		rand.Read(morphed[padStart:])
	}
	return morphed
}

// StripMorphedPayload extracts the original data from a morphed payload.
func StripMorphedPayload(morphed []byte) ([]byte, error) {
	if len(morphed) < 2 {
		return nil, fmt.Errorf("reflex: morphed payload too short: %d bytes", len(morphed))
	}
	actualLen := int(binary.BigEndian.Uint16(morphed[:2]))
	if actualLen > len(morphed)-2 {
		return nil, fmt.Errorf("reflex: morphing length prefix %d exceeds available %d", actualLen, len(morphed)-2)
	}
	return morphed[2 : 2+actualLen], nil
}

// ---- Control frame helpers ----

// EncodePaddingControl builds the payload for a PADDING_CTRL frame.
func EncodePaddingControl(targetSize int) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(targetSize))
	return buf
}

// EncodeTimingControl builds the payload for a TIMING_CTRL frame.
func EncodeTimingControl(delay time.Duration) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(delay.Milliseconds()))
	return buf
}

// ---- Profile construction from captured data ----

// CreateProfileFromCapture builds a TrafficProfile from raw packet sizes
// and inter-packet delays observed in a real traffic capture.
func CreateProfileFromCapture(name string, packetSizes []int, delays []time.Duration) *TrafficProfile {
	return &TrafficProfile{
		Name:        name,
		PacketSizes: calculateSizeDistribution(packetSizes),
		Delays:      calculateDelayDistribution(delays),
	}
}

func calculateSizeDistribution(values []int) []PacketSizeDist {
	if len(values) == 0 {
		return nil
	}
	freq := make(map[int]int)
	for _, v := range values {
		freq[v]++
	}
	total := len(values)
	dist := make([]PacketSizeDist, 0, len(freq))
	for size, count := range freq {
		dist = append(dist, PacketSizeDist{
			Size:   size,
			Weight: float64(count) / float64(total),
		})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Size < dist[j].Size })
	return dist
}

func calculateDelayDistribution(values []time.Duration) []DelayDist {
	if len(values) == 0 {
		return nil
	}
	freq := make(map[time.Duration]int)
	for _, v := range values {
		freq[v]++
	}
	total := len(values)
	dist := make([]DelayDist, 0, len(freq))
	for delay, count := range freq {
		dist = append(dist, DelayDist{
			Delay:  delay,
			Weight: float64(count) / float64(total),
		})
	}
	sort.Slice(dist, func(i, j int) bool { return dist[i].Delay < dist[j].Delay })
	return dist
}

// ---- Statistical testing ----

// KolmogorovSmirnovStat computes a discrete two-sample KS test statistic D
// between the observed sample distribution and the expected distribution from
// a profile. It merges all unique values from both distributions and steps
// through them in order, comparing cumulative probabilities.
// A small D indicates the two distributions are similar.
func KolmogorovSmirnovStat(observed []int, profile *TrafficProfile) float64 {
	if len(observed) == 0 || len(profile.PacketSizes) == 0 {
		return 1.0
	}

	n := float64(len(observed))

	observedCounts := make(map[int]int)
	for _, v := range observed {
		observedCounts[v]++
	}

	theoreticalWeights := make(map[int]float64)
	for _, d := range profile.PacketSizes {
		theoreticalWeights[d.Size] = d.Weight
	}

	allSizes := make(map[int]bool)
	for s := range observedCounts {
		allSizes[s] = true
	}
	for s := range theoreticalWeights {
		allSizes[s] = true
	}
	sortedSizes := make([]int, 0, len(allSizes))
	for s := range allSizes {
		sortedSizes = append(sortedSizes, s)
	}
	sort.Ints(sortedSizes)

	maxD := 0.0
	empCum := 0.0
	theCum := 0.0
	for _, size := range sortedSizes {
		empCum += float64(observedCounts[size]) / n
		theCum += theoreticalWeights[size]
		if d := math.Abs(empCum - theCum); d > maxD {
			maxD = d
		}
	}
	return maxD
}
