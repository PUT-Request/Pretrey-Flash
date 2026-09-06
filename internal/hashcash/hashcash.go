package hashcash

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ReplayEntry struct {
	ExpiresAt time.Time
}

var (
	usedHashcash  = make(map[string]time.Time)
	usedMu        sync.Mutex
	lastPrune     time.Time
)

func VerifyHashcashServer(challenge, nonce string, difficulty int) bool {
	input := challenge + ":" + nonce
	hash := sha256.Sum256([]byte(input))

	zeroBits := 0
	for _, b := range hash {
		if b == 0 {
			zeroBits += 8
		} else {
			zeroBits += bits.LeadingZeros8(b)
			break
		}
	}

	return zeroBits >= difficulty
}

func IsReplay(entryKey string) bool {
	usedMu.Lock()
	defer usedMu.Unlock()

	now := time.Now()
	if now.Sub(lastPrune) > 30*time.Second {
		for k, v := range usedHashcash {
			if v.Before(now) {
				delete(usedHashcash, k)
			}
		}
		lastPrune = now
	}

	_, exists := usedHashcash[entryKey]
	return exists
}

func MarkReplayUsed(entryKey string, ttl time.Duration) {
	usedMu.Lock()
	defer usedMu.Unlock()
	usedHashcash[entryKey] = time.Now().Add(ttl)
}

func FormatReplayKey(ip, challenge, nonce string) string {
	return ip + ":" + challenge + ":" + nonce
}

func ParseDifficulty(diffStr string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(diffStr))
}

func ValidateNoncePattern(nonce string) bool {
	if len(nonce) == 0 || len(nonce) > 20 {
		return false
	}
	for _, c := range nonce {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func HashcashTimestampTTL() time.Duration {
	return 2 * time.Minute
}

func HashcashReplayTTL() time.Duration {
	return 5 * time.Minute
}

func GenerateDifficultyError(difficulty int) string {
	return fmt.Sprintf("Invalid spam protection for custom URL (difficulty %d required)", difficulty)
}
