package dashboard

import (
	"time"

	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

// DashboardEvent wraps a PipelineEvent with a unique dashboard ID.
type DashboardEvent struct {
	ID string `json:"id"`
	pipeline.PipelineEvent
}

// WSMessage is the envelope for all WebSocket messages.
type WSMessage struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

// StatsSnapshot is a point-in-time snapshot of accumulated statistics.
type StatsSnapshot struct {
	TotalRequests uint64            `json:"total_requests"`
	BlockedCount  uint64            `json:"blocked_count"`
	AllowedCount  uint64            `json:"allowed_count"`
	AvgRiskScore  float64           `json:"avg_risk_score"`
	ActionCounts  map[string]uint64 `json:"action_counts"`
	RuleCounts    map[string]uint64 `json:"rule_counts"`
	IntentCounts  map[string]uint64 `json:"intent_counts"`
	RiskHistogram [10]uint64        `json:"risk_histogram"`
	TimeSeries    []TimeSeriesPoint `json:"time_series"`
}

// TimeSeriesPoint is a single point in the 60-minute time series.
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     uint64    `json:"count"`
	Blocked   uint64    `json:"blocked"`
}

// InitialState is sent to clients on WebSocket connect.
type InitialState struct {
	Events []*DashboardEvent `json:"events"`
	Stats  *StatsSnapshot    `json:"stats"`
	Policy *policy.Policy    `json:"policy"`
}
