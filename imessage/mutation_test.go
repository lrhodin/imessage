//go:build mutation

package imessage

import (
	"testing"

	"github.com/gtramontina/ooze"
)

func TestMutation(t *testing.T) {
	ooze.Release(
		t,
		ooze.WithTestCommand("go test -count=1 ./imessage/..."),
		ooze.WithMinimumThreshold(0.70),
		ooze.Parallel(),
	)
}
