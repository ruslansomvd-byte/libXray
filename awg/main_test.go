package awg

import (
	"os"
	"testing"
	"time"
)

// В тестах ключи без сервера: рукопожатия не будет, и ждать его 3 с на
// каждый запуск движка незачем.
func TestMain(m *testing.M) {
	handshakeWait = 50 * time.Millisecond
	os.Exit(m.Run())
}
