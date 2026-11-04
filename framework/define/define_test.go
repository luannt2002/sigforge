package define

import "testing"

func TestServiceName(t *testing.T) {
	if ServiceName != "sigforge" {
		t.Errorf("ServiceName = %q, want sigforge", ServiceName)
	}
}
