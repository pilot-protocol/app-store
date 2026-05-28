package manifest

import (
	"strings"
	"testing"
)

func TestMarshal_Roundtrip(t *testing.T) {
	t.Parallel()
	m := &Manifest{
		ID:              "io.test.app",
		ManifestVersion: 1,
		AppVersion:      "0.1.0",
		Protection:      "shareable",
		Binary:          Binary{Runtime: "go", Path: "bin/x", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	body, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(body), `"io.test.app"`) {
		t.Errorf("body missing app ID: %q", body)
	}
}
