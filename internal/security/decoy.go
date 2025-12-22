// Package security provides advanced security features for TorForge
package security

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
)

// DecoyTrafficConfig configures the decoy traffic generator
type DecoyTrafficConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Percentage  int    `yaml:"percentage"`      // Percentage of fake traffic (0-100)
	MinInterval int    `yaml:"min_interval_ms"` // Min ms between requests
	MaxInterval int    `yaml:"max_interval_ms"` // Max ms between requests
	UserAgent   string `yaml:"user_agent"`
}

// DecoyTrafficGenerator generates fake HTTP traffic to confuse traffic analysis
type DecoyTrafficGenerator struct {
	mu          sync.RWMutex
	running     bool
	percentage  int
	minInterval time.Duration
	maxInterval time.Duration

	// SOCKS proxy address
	proxyAddr string

	// Stats
	requestsSent   int64
	bytesGenerated int64

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// HTTP client via Tor (reserved for future SOCKS-aware requests)
	_client *http.Client
}

// Popular sites to generate decoy traffic to
var decoyTargets = []string{
	"https://www.google.com/search?q=weather",
	"https://www.youtube.com/",
	"https://www.wikipedia.org/",
	"https://www.reddit.com/",
	"https://www.amazon.com/",
	"https://www.facebook.com/",
	"https://www.twitter.com/",
	"https://www.instagram.com/",
	"https://www.linkedin.com/",
	"https://www.netflix.com/",
	"https://www.spotify.com/",
	"https://www.apple.com/",
	"https://www.microsoft.com/",
	"https://www.github.com/",
	"https://www.stackoverflow.com/",
	"https://news.ycombinator.com/",
	"https://www.nytimes.com/",
	"https://www.bbc.com/",
	"https://www.cnn.com/",
	"https://www.theguardian.com/",
}

// NewDecoyTrafficGenerator creates a new decoy traffic generator
func NewDecoyTrafficGenerator(cfg *DecoyTrafficConfig, proxyAddr string) *DecoyTrafficGenerator {
	if cfg == nil || !cfg.Enabled {
		return &DecoyTrafficGenerator{running: false}
	}

	minInterval := time.Duration(cfg.MinInterval) * time.Millisecond
	maxInterval := time.Duration(cfg.MaxInterval) * time.Millisecond

	if minInterval == 0 {
		minInterval = 500 * time.Millisecond
	}
	if maxInterval == 0 {
		maxInterval = 5000 * time.Millisecond
	}

	return &DecoyTrafficGenerator{
		percentage:  cfg.Percentage,
		minInterval: minInterval,
		maxInterval: maxInterval,
		proxyAddr:   proxyAddr,
	}
}

// Start begins generating decoy traffic
func (d *DecoyTrafficGenerator) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = true
	d.ctx, d.cancel = context.WithCancel(ctx)
	d.mu.Unlock()

	log := logger.WithComponent("decoy")
	log.Info().
		Int("percentage", d.percentage).
		Msg("🎭 Decoy traffic generator started")

	// Start multiple goroutines based on percentage
	numWorkers := d.percentage / 10
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers > 10 {
		numWorkers = 10
	}

	for i := 0; i < numWorkers; i++ {
		go d.trafficWorker(i)
	}

	return nil
}

// trafficWorker generates decoy requests
func (d *DecoyTrafficGenerator) trafficWorker(id int) {
	log := logger.WithComponent("decoy")

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Random delay
			delay := d.randomDuration(d.minInterval, d.maxInterval)
			time.Sleep(delay)

			// Pick random target
			target := d.randomTarget()

			// Make request (don't care about response)
			go d.makeDecoyRequest(target)

			atomic.AddInt64(&d.requestsSent, 1)

			if d.requestsSent%100 == 0 {
				log.Debug().
					Int64("requests", d.requestsSent).
					Msg("decoy traffic stats")
			}
		}
	}
}

// makeDecoyRequest makes a fake HTTP request
func (d *DecoyTrafficGenerator) makeDecoyRequest(url string) {
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	// Randomize headers to look more real
	req.Header.Set("User-Agent", d.randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	// Use default HTTP client (will go through iptables → Tor)
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read some of the response to generate traffic
	buf := make([]byte, 4096)
	if n, err := resp.Body.Read(buf); err == nil {
		atomic.AddInt64(&d.bytesGenerated, int64(n))
	}
}

// randomTarget picks a random decoy target
func (d *DecoyTrafficGenerator) randomTarget() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(decoyTargets))))
	if err != nil {
		return decoyTargets[0] // Fallback to first target
	}
	return decoyTargets[n.Int64()]
}

// randomDuration returns random duration in range
func (d *DecoyTrafficGenerator) randomDuration(min, max time.Duration) time.Duration {
	diff := max - min
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return min + diff/2 // Fallback to midpoint
	}
	return min + time.Duration(n.Int64())
}

// randomUserAgent returns a random user agent
func (d *DecoyTrafficGenerator) randomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	if err != nil {
		return userAgents[0] // Fallback to first user agent
	}
	return userAgents[n.Int64()]
}

// Stop stops the decoy traffic generator
func (d *DecoyTrafficGenerator) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	d.running = false
	if d.cancel != nil {
		d.cancel()
	}

	log := logger.WithComponent("decoy")
	log.Info().
		Int64("total_requests", d.requestsSent).
		Int64("bytes_generated", d.bytesGenerated).
		Msg("decoy traffic generator stopped")
}

// GetStats returns current stats
func (d *DecoyTrafficGenerator) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"running":         d.running,
		"requests_sent":   atomic.LoadInt64(&d.requestsSent),
		"bytes_generated": atomic.LoadInt64(&d.bytesGenerated),
		"percentage":      d.percentage,
	}
}

// IsRunning returns whether the generator is running
func (d *DecoyTrafficGenerator) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}
