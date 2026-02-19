package reflex

import (
	"bytes"
	"crypto/rand"
	"io"
	"math"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------------ profiles

func TestLookupProfile(t *testing.T) {
	if p := LookupProfile("youtube"); p == nil {
		t.Fatal("youtube profile should exist")
	}
	if p := LookupProfile("zoom"); p == nil {
		t.Fatal("zoom profile should exist")
	}
	if p := LookupProfile("nonexistent"); p != nil {
		t.Fatal("nonexistent profile should be nil")
	}
}

func TestProfileWeightsSum(t *testing.T) {
	for name, profile := range Profiles {
		sizeSum := 0.0
		for _, d := range profile.PacketSizes {
			sizeSum += d.Weight
		}
		if math.Abs(sizeSum-1.0) > 0.01 {
			t.Errorf("profile %q: packet size weights sum to %.4f, want ~1.0", name, sizeSum)
		}
		delaySum := 0.0
		for _, d := range profile.Delays {
			delaySum += d.Weight
		}
		if math.Abs(delaySum-1.0) > 0.01 {
			t.Errorf("profile %q: delay weights sum to %.4f, want ~1.0", name, delaySum)
		}
	}
}

func TestProfilePacketSizesInRange(t *testing.T) {
	for name, profile := range Profiles {
		for _, d := range profile.PacketSizes {
			if d.Size < 1 || d.Size > 65535 {
				t.Errorf("profile %q: invalid packet size %d", name, d.Size)
			}
		}
	}
}

// ------------------------------------------------------------------ sampling

func TestGetPacketSize_Distribution(t *testing.T) {
	profile := LookupProfile("youtube")
	if profile == nil {
		t.Fatal("youtube profile not found")
	}

	counts := make(map[int]int)
	const N = 10000
	for i := 0; i < N; i++ {
		size := profile.GetPacketSize()
		counts[size]++
	}

	for _, d := range profile.PacketSizes {
		count := counts[d.Size]
		observed := float64(count) / float64(N)
		if math.Abs(observed-d.Weight) > 0.05 {
			t.Errorf("size %d: observed %.3f, expected %.3f (diff > 0.05)", d.Size, observed, d.Weight)
		}
	}
}

func TestGetDelay_Distribution(t *testing.T) {
	profile := LookupProfile("zoom")
	if profile == nil {
		t.Fatal("zoom profile not found")
	}

	counts := make(map[time.Duration]int)
	const N = 10000
	for i := 0; i < N; i++ {
		delay := profile.GetDelay()
		counts[delay]++
	}

	for _, d := range profile.Delays {
		count := counts[d.Delay]
		observed := float64(count) / float64(N)
		if math.Abs(observed-d.Weight) > 0.05 {
			t.Errorf("delay %v: observed %.3f, expected %.3f (diff > 0.05)", d.Delay, observed, d.Weight)
		}
	}
}

func TestGetPacketSize_AllSizesAppear(t *testing.T) {
	profile := LookupProfile("youtube")
	seen := make(map[int]bool)
	for i := 0; i < 5000; i++ {
		seen[profile.GetPacketSize()] = true
	}
	for _, d := range profile.PacketSizes {
		if !seen[d.Size] {
			t.Errorf("size %d never appeared in 5000 samples", d.Size)
		}
	}
}

// ------------------------------------------------------------------ overrides

func TestSetNextPacketSize(t *testing.T) {
	profile := LookupProfile("youtube")

	profile.SetNextPacketSize(9999)
	got := profile.GetPacketSize()
	if got != 9999 {
		t.Fatalf("expected override 9999, got %d", got)
	}

	got2 := profile.GetPacketSize()
	found := false
	for _, d := range profile.PacketSizes {
		if d.Size == got2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("after override consumed, got unexpected size %d", got2)
	}
}

func TestSetNextDelay(t *testing.T) {
	profile := LookupProfile("zoom")

	profile.SetNextDelay(999 * time.Millisecond)
	got := profile.GetDelay()
	if got != 999*time.Millisecond {
		t.Fatalf("expected override 999ms, got %v", got)
	}

	got2 := profile.GetDelay()
	found := false
	for _, d := range profile.Delays {
		if d.Delay == got2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("after override consumed, got unexpected delay %v", got2)
	}
}

// ------------------------------------------------------------------ concurrency

func TestProfileConcurrency(t *testing.T) {
	profile := LookupProfile("youtube")
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				profile.GetPacketSize()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				profile.GetDelay()
			}
		}()
	}
	wg.Wait()
}

// ------------------------------------------------------------------ padding

func TestBuildMorphedPayload(t *testing.T) {
	data := []byte("hello world")
	target := 200

	morphed := BuildMorphedPayload(data, target)
	if len(morphed) != target {
		t.Fatalf("expected %d bytes, got %d", target, len(morphed))
	}

	// Verify length prefix.
	storedLen := int(morphed[0])<<8 | int(morphed[1])
	if storedLen != len(data) {
		t.Fatalf("length prefix: got %d, want %d", storedLen, len(data))
	}

	// Verify data.
	if !bytes.Equal(morphed[2:2+len(data)], data) {
		t.Fatal("data portion mismatch")
	}
}

func TestBuildMorphedPayload_MinSize(t *testing.T) {
	data := []byte("x")
	morphed := BuildMorphedPayload(data, 1)
	if len(morphed) < 3 {
		t.Fatalf("minimum morphed size should be 3, got %d", len(morphed))
	}
}

func TestStripMorphedPayload(t *testing.T) {
	original := []byte("test data for morphing")
	morphed := BuildMorphedPayload(original, 500)

	stripped, err := StripMorphedPayload(morphed)
	if err != nil {
		t.Fatalf("StripMorphedPayload: %v", err)
	}
	if !bytes.Equal(stripped, original) {
		t.Fatalf("stripped data mismatch: got %q, want %q", stripped, original)
	}
}

func TestStripMorphedPayload_TooShort(t *testing.T) {
	_, err := StripMorphedPayload([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for too-short payload")
	}
}

func TestStripMorphedPayload_InvalidLength(t *testing.T) {
	bad := []byte{0xFF, 0xFF, 0x01}
	_, err := StripMorphedPayload(bad)
	if err == nil {
		t.Fatal("expected error for invalid length prefix")
	}
}

func TestBuildStripRoundtrip(t *testing.T) {
	for _, dataLen := range []int{0, 1, 50, 500, 1398} {
		data := make([]byte, dataLen)
		io.ReadFull(rand.Reader, data)

		targetSize := dataLen + 2 + 50 // data + prefix + padding
		morphed := BuildMorphedPayload(data, targetSize)
		stripped, err := StripMorphedPayload(morphed)
		if err != nil {
			t.Fatalf("dataLen=%d: StripMorphedPayload: %v", dataLen, err)
		}
		if !bytes.Equal(stripped, data) {
			t.Fatalf("dataLen=%d: round-trip mismatch", dataLen)
		}
	}
}

func TestBuildStripRoundtrip_EmptyData(t *testing.T) {
	morphed := BuildMorphedPayload(nil, 100)
	stripped, err := StripMorphedPayload(morphed)
	if err != nil {
		t.Fatalf("StripMorphedPayload: %v", err)
	}
	if len(stripped) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(stripped))
	}
}

// ------------------------------------------------------------------ control frames

func TestEncodePaddingControl(t *testing.T) {
	buf := EncodePaddingControl(1400)
	if len(buf) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(buf))
	}
	val := int(buf[0])<<8 | int(buf[1])
	if val != 1400 {
		t.Fatalf("expected 1400, got %d", val)
	}
}

func TestEncodeTimingControl(t *testing.T) {
	buf := EncodeTimingControl(50 * time.Millisecond)
	if len(buf) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(buf))
	}
}

// ------------------------------------------------------------------ profile creation from capture

func TestCreateProfileFromCapture(t *testing.T) {
	sizes := []int{100, 200, 100, 300, 200, 100}
	delays := []time.Duration{
		10 * time.Millisecond, 20 * time.Millisecond,
		10 * time.Millisecond, 30 * time.Millisecond,
	}

	profile := CreateProfileFromCapture("test-capture", sizes, delays)
	if profile.Name != "test-capture" {
		t.Fatal("name mismatch")
	}
	if len(profile.PacketSizes) != 3 {
		t.Fatalf("expected 3 distinct sizes, got %d", len(profile.PacketSizes))
	}
	if len(profile.Delays) != 3 {
		t.Fatalf("expected 3 distinct delays, got %d", len(profile.Delays))
	}

	totalWeight := 0.0
	for _, d := range profile.PacketSizes {
		totalWeight += d.Weight
	}
	if math.Abs(totalWeight-1.0) > 0.001 {
		t.Fatalf("size weights sum to %.4f", totalWeight)
	}
}

func TestCreateProfileFromCapture_Empty(t *testing.T) {
	profile := CreateProfileFromCapture("empty", nil, nil)
	if len(profile.PacketSizes) != 0 {
		t.Fatal("expected no size dist")
	}
	if len(profile.Delays) != 0 {
		t.Fatal("expected no delay dist")
	}
}

// ------------------------------------------------------------------ KS test

func TestKolmogorovSmirnovStat_PerfectMatch(t *testing.T) {
	profile := LookupProfile("youtube")

	const N = 10000
	samples := make([]int, N)
	for i := 0; i < N; i++ {
		samples[i] = profile.GetPacketSize()
	}

	d := KolmogorovSmirnovStat(samples, profile)
	// For large N from the same discrete distribution, D should be very small.
	if d > 0.03 {
		t.Errorf("KS statistic D=%.4f exceeds 0.03 — profile self-match failed", d)
	}
}

func TestKolmogorovSmirnovStat_Mismatch(t *testing.T) {
	youtube := LookupProfile("youtube")
	zoom := LookupProfile("zoom")

	// Generate samples from YouTube but test against Zoom — D should be large.
	const N = 2000
	samples := make([]int, N)
	for i := 0; i < N; i++ {
		samples[i] = youtube.GetPacketSize()
	}

	d := KolmogorovSmirnovStat(samples, zoom)
	if d < 0.05 {
		t.Errorf("KS statistic D=%.4f is unexpectedly small for mismatched profiles", d)
	}
}

func TestKolmogorovSmirnovStat_Empty(t *testing.T) {
	profile := LookupProfile("youtube")
	d := KolmogorovSmirnovStat(nil, profile)
	if d != 1.0 {
		t.Errorf("expected 1.0 for empty samples, got %.4f", d)
	}
}

// ------------------------------------------------------------------ session morphing round-trip

func TestWriteReadMorphedFrame(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	profile := &TrafficProfile{
		Name: "test",
		PacketSizes: []PacketSizeDist{
			{Size: 200, Weight: 1.0},
		},
		Delays: []DelayDist{
			{Delay: 0, Weight: 1.0},
		},
	}
	sender.SetProfile(profile)
	receiver.SetProfile(profile)

	original := []byte("morphed round-trip test")
	var buf bytes.Buffer
	if err := sender.WriteFrameMorphed(&buf, FrameTypeData, original); err != nil {
		t.Fatalf("WriteFrameMorphed: %v", err)
	}

	frame, err := receiver.ReadFrameMorphed(&buf)
	if err != nil {
		t.Fatalf("ReadFrameMorphed: %v", err)
	}
	if frame.Type != FrameTypeData {
		t.Fatalf("expected FrameTypeData, got 0x%02x", frame.Type)
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, original)
	}
}

func TestWriteReadMorphed_MultipleFrames(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	profile := &TrafficProfile{
		Name: "test-multi",
		PacketSizes: []PacketSizeDist{
			{Size: 300, Weight: 1.0},
		},
		Delays: []DelayDist{
			{Delay: 0, Weight: 1.0},
		},
	}
	sender.SetProfile(profile)
	receiver.SetProfile(profile)

	messages := [][]byte{
		[]byte("first"),
		[]byte("second message here"),
		[]byte("third"),
	}

	var buf bytes.Buffer
	for _, msg := range messages {
		if err := sender.WriteFrameMorphed(&buf, FrameTypeData, msg); err != nil {
			t.Fatalf("WriteFrameMorphed: %v", err)
		}
	}

	for i, want := range messages {
		frame, err := receiver.ReadFrameMorphed(&buf)
		if err != nil {
			t.Fatalf("ReadFrameMorphed[%d]: %v", i, err)
		}
		if !bytes.Equal(frame.Payload, want) {
			t.Fatalf("frame[%d]: got %q, want %q", i, frame.Payload, want)
		}
	}
}

func TestWriteReadMorphed_LargeDataSplit(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	profile := &TrafficProfile{
		Name: "small-target",
		PacketSizes: []PacketSizeDist{
			{Size: 50, Weight: 1.0},
		},
		Delays: []DelayDist{
			{Delay: 0, Weight: 1.0},
		},
	}
	sender.SetProfile(profile)
	receiver.SetProfile(profile)

	large := make([]byte, 200)
	io.ReadFull(rand.Reader, large)

	var buf bytes.Buffer
	if err := sender.WriteFrameMorphed(&buf, FrameTypeData, large); err != nil {
		t.Fatalf("WriteFrameMorphed: %v", err)
	}

	// Large data should be split across multiple frames.
	var reassembled []byte
	for buf.Len() > 0 {
		frame, err := receiver.ReadFrameMorphed(&buf)
		if err != nil {
			t.Fatalf("ReadFrameMorphed: %v", err)
		}
		reassembled = append(reassembled, frame.Payload...)
	}

	if !bytes.Equal(reassembled, large) {
		t.Fatal("reassembled data does not match original")
	}
}

func TestWriteReadMorphed_NonDataFramePassthrough(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	profile := &TrafficProfile{
		Name: "test",
		PacketSizes: []PacketSizeDist{
			{Size: 100, Weight: 1.0},
		},
		Delays: []DelayDist{
			{Delay: 0, Weight: 1.0},
		},
	}
	sender.SetProfile(profile)
	receiver.SetProfile(profile)

	var buf bytes.Buffer
	// Close frame should not be morphed.
	if err := sender.WriteFrameMorphed(&buf, FrameTypeClose, nil); err != nil {
		t.Fatalf("WriteFrameMorphed close: %v", err)
	}

	frame, err := receiver.ReadFrameMorphed(&buf)
	if err != nil {
		t.Fatalf("ReadFrameMorphed close: %v", err)
	}
	if frame.Type != FrameTypeClose {
		t.Fatalf("expected FrameTypeClose, got 0x%02x", frame.Type)
	}
}

func TestWriteReadMorphed_NoProfileFallsBackToPlain(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	original := []byte("no morphing")
	var buf bytes.Buffer
	if err := sender.WriteFrameMorphed(&buf, FrameTypeData, original); err != nil {
		t.Fatalf("WriteFrameMorphed: %v", err)
	}

	// Without a profile, ReadFrameMorphed should return plaintext as-is.
	frame, err := receiver.ReadFrameMorphed(&buf)
	if err != nil {
		t.Fatalf("ReadFrameMorphed: %v", err)
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Fatalf("got %q, want %q", frame.Payload, original)
	}
}

// ------------------------------------------------------------------ morphing statistical verification

func TestMorphingProducesCorrectSizeDistribution(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	// Use a profile with zero delays to avoid slow tests.
	testProfile := &TrafficProfile{
		Name: "youtube-nodelay",
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
			{Delay: 0, Weight: 1.0},
		},
	}

	const N = 2000
	frameSizes := make([]int, 0, N)

	// Use small data (50 bytes) that fits within all target sizes.
	data := make([]byte, 50)

	for i := 0; i < N; i++ {
		sender, _ := NewSession(key)
		sender.SetProfile(testProfile)

		var buf bytes.Buffer
		sender.WriteFrameMorphed(&buf, FrameTypeData, data)

		wireSize := buf.Len()
		plaintextSize := wireSize - 3 - 16 // header(3) + AEAD tag(16)
		frameSizes = append(frameSizes, plaintextSize)
	}

	d := KolmogorovSmirnovStat(frameSizes, testProfile)
	if d > 0.05 {
		t.Errorf("morphed frame sizes don't match profile: D=%.4f", d)
	}
}

func TestSetProfile(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	session, _ := NewSession(key)
	if session.Profile() != nil {
		t.Fatal("profile should be nil initially")
	}

	profile := LookupProfile("youtube")
	session.SetProfile(profile)
	if session.Profile() != profile {
		t.Fatal("profile should be set")
	}

	session.SetProfile(nil)
	if session.Profile() != nil {
		t.Fatal("profile should be nil after clearing")
	}
}

func TestSampleSizeEmptyDist(t *testing.T) {
	got := sampleSize(nil)
	if got != 512 {
		t.Fatalf("expected default 512, got %d", got)
	}
}

func TestSampleDelayEmptyDist(t *testing.T) {
	got := sampleDelay(nil)
	if got != 10*time.Millisecond {
		t.Fatalf("expected default 10ms, got %v", got)
	}
}
