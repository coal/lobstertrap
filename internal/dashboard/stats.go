package dashboard

import (
	"sync"
	"time"
)

const timeSeriesMinutes = 60

// Stats accumulates real-time statistics from pipeline events.
type Stats struct {
	mu sync.RWMutex

	totalRequests uint64
	blockedCount  uint64
	allowedCount  uint64
	riskScoreSum  float64

	actionCounts map[string]uint64
	ruleCounts   map[string]uint64
	intentCounts map[string]uint64
	riskHist     [10]uint64 // buckets: [0.0-0.1), [0.1-0.2), ..., [0.9-1.0]

	// Per-minute buckets for the last 60 minutes
	timeBuckets [timeSeriesMinutes]timeBucket
}

type timeBucket struct {
	minute  time.Time // truncated to minute
	count   uint64
	blocked uint64
}

// NewStats creates a new stats accumulator.
func NewStats() *Stats {
	return &Stats{
		actionCounts: make(map[string]uint64),
		ruleCounts:   make(map[string]uint64),
		intentCounts: make(map[string]uint64),
	}
}

// Record ingests a single pipeline event.
func (s *Stats) Record(event *DashboardEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalRequests++

	if event.Blocked {
		s.blockedCount++
	} else {
		s.allowedCount++
	}

	if event.Metadata != nil {
		s.riskScoreSum += event.Metadata.RiskScore

		// Risk histogram: bucket index = floor(risk * 10), capped at 9
		bucket := int(event.Metadata.RiskScore * 10)
		if bucket > 9 {
			bucket = 9
		}
		s.riskHist[bucket]++

		// Intent distribution
		if event.Metadata.IntentCategory != "" {
			s.intentCounts[event.Metadata.IntentCategory]++
		}
	}

	// Action distribution
	s.actionCounts[string(event.Action)]++

	// Rule distribution
	if event.RuleName != "" {
		s.ruleCounts[event.RuleName]++
	}

	// Time series
	now := event.Timestamp.Truncate(time.Minute)
	idx := now.Minute() % timeSeriesMinutes
	if s.timeBuckets[idx].minute != now {
		s.timeBuckets[idx] = timeBucket{minute: now}
	}
	s.timeBuckets[idx].count++
	if event.Blocked {
		s.timeBuckets[idx].blocked++
	}
}

// Snapshot returns a point-in-time copy of the stats.
func (s *Stats) Snapshot() *StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := &StatsSnapshot{
		TotalRequests: s.totalRequests,
		BlockedCount:  s.blockedCount,
		AllowedCount:  s.allowedCount,
		ActionCounts:  copyMap(s.actionCounts),
		RuleCounts:    copyMap(s.ruleCounts),
		IntentCounts:  copyMap(s.intentCounts),
		RiskHistogram: s.riskHist,
	}

	if s.totalRequests > 0 {
		snap.AvgRiskScore = s.riskScoreSum / float64(s.totalRequests)
	}

	// Build time series from buckets (last 60 minutes, chronological)
	now := time.Now().UTC().Truncate(time.Minute)
	cutoff := now.Add(-timeSeriesMinutes * time.Minute)
	for i := 0; i < timeSeriesMinutes; i++ {
		t := cutoff.Add(time.Duration(i+1) * time.Minute)
		idx := t.Minute() % timeSeriesMinutes
		b := s.timeBuckets[idx]
		if b.minute == t {
			snap.TimeSeries = append(snap.TimeSeries, TimeSeriesPoint{
				Timestamp: b.minute,
				Count:     b.count,
				Blocked:   b.blocked,
			})
		} else {
			snap.TimeSeries = append(snap.TimeSeries, TimeSeriesPoint{
				Timestamp: t,
				Count:     0,
				Blocked:   0,
			})
		}
	}

	return snap
}

func copyMap(m map[string]uint64) map[string]uint64 {
	c := make(map[string]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
