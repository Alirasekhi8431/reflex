package grading

import "testing"

// TestGradingProtocolConstants ensures REFX magic and frame types are defined.
func TestGradingProtocolConstants(t *testing.T) {
	if ReflexMagicLen != 4 {
		t.Errorf("ReflexMagicLen: want 4, got %d", ReflexMagicLen)
	}
	if FrameTypeData == 0 && FrameTypePadding == 0 && FrameTypeTiming == 0 {
		t.Error("at least one FrameType should be non-zero")
	}
}
