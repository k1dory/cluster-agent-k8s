package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// StateCounts is what the state gauges report: sandboxes by status and the runs that are not
// finished (queued, running) by status. The source fills every status it knows, zeros
// included, so a series does not vanish when its count drops to nothing.
type StateCounts struct {
	Sandboxes map[string]int
	Runs      map[string]int
}

// StateSource reads the counts from the store; it must be one bounded query, not a walk of
// every record.
type StateSource func(ctx context.Context) (StateCounts, error)

var (
	sandboxesDesc = prometheus.NewDesc("sandboxd_sandboxes", "Sandboxes by status (every replica reports the same shared state).", []string{"status"}, nil)
	runsDesc      = prometheus.NewDesc("sandboxd_runs", "Runs not finished yet (queued, running) by status.", []string{"status"}, nil)
	queueDesc     = prometheus.NewDesc("sandboxd_run_queue_depth", "Runs queued and not yet handed to an agent.", nil, nil)
)

// stateCollector reads the counts when scraped, at most once per every: several Prometheus
// replicas scraping every replica of sandboxd must not each cost a query against the one
// database. A failed read reports nothing (the series go stale rather than show old numbers
// as current).
type stateCollector struct {
	src     StateSource
	every   time.Duration
	timeout time.Duration

	mu   sync.Mutex
	at   time.Time
	last *StateCounts
}

// NewStateCollector returns the collector of the state gauges; register it on Registry.
func NewStateCollector(src StateSource, every time.Duration) prometheus.Collector {
	return &stateCollector{src: src, every: every, timeout: 5 * time.Second}
}

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sandboxesDesc
	ch <- runsDesc
	ch <- queueDesc
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	if counts == nil {
		return
	}
	for st, n := range counts.Sandboxes {
		ch <- prometheus.MustNewConstMetric(sandboxesDesc, prometheus.GaugeValue, float64(n), st)
	}
	for st, n := range counts.Runs {
		ch <- prometheus.MustNewConstMetric(runsDesc, prometheus.GaugeValue, float64(n), st)
	}
	ch <- prometheus.MustNewConstMetric(queueDesc, prometheus.GaugeValue, float64(counts.Runs["queued"]))
}

func (c *stateCollector) read() *StateCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last != nil && time.Since(c.at) < c.every {
		return c.last
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	counts, err := c.src(ctx)
	c.at = time.Now()
	if err != nil {
		c.last = nil
		return nil
	}
	c.last = &counts
	return c.last
}
