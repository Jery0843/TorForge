// Package ml provides machine learning utilities for TorForge
package ml

import (
	"math"
	"time"
)

// Normalization constants (based on expected ranges)
const (
	maxLatencyMs     = 2000.0  // 2 seconds max expected latency
	maxBandwidthKbps = 50000.0 // 50 Mbps max expected bandwidth
	maxSamples       = 1000.0  // More samples = more reliable
	maxAgeHours      = 168.0   // 1 week old data considered stale
)

// NormalizeLatency normalizes latency to 0-1 (lower is better, so we invert)
func NormalizeLatency(latencyMs float64) float64 {
	if latencyMs <= 0 {
		return 1.0 // No latency = perfect
	}
	if latencyMs >= maxLatencyMs {
		return 0.0 // Very high latency = bad
	}
	// Invert: low latency = high score
	return 1.0 - (latencyMs / maxLatencyMs)
}

// NormalizeBandwidth normalizes bandwidth to 0-1 (higher is better)
func NormalizeBandwidth(bandwidthKbps float64) float64 {
	if bandwidthKbps <= 0 {
		return 0.0
	}
	if bandwidthKbps >= maxBandwidthKbps {
		return 1.0
	}
	return bandwidthKbps / maxBandwidthKbps
}

// NormalizeSamples normalizes sample count to 0-1 (more is better for confidence)
func NormalizeSamples(samples int) float64 {
	if samples <= 0 {
		return 0.0
	}
	if float64(samples) >= maxSamples {
		return 1.0
	}
	// Logarithmic scaling - diminishing returns after initial samples
	return math.Log1p(float64(samples)) / math.Log1p(maxSamples)
}

// NormalizeTimeOfDay normalizes hour to 0-1
func NormalizeTimeOfDay(t time.Time) float64 {
	return float64(t.Hour()) / 24.0
}

// NormalizeRecency normalizes how recent the data is (1 = now, 0 = very old)
func NormalizeRecency(lastSeen time.Time) float64 {
	age := time.Since(lastSeen).Hours()
	if age <= 0 {
		return 1.0
	}
	if age >= maxAgeHours {
		return 0.0
	}
	return 1.0 - (age / maxAgeHours)
}

// CircuitObservation represents a raw observation from circuit performance
type CircuitObservation struct {
	ExitNode      string
	Country       string
	LatencyMs     float64
	BandwidthKbps float64
	Success       bool
	Timestamp     time.Time
}

// ToFeatures converts an observation to normalized features
func (o *CircuitObservation) ToFeatures(sampleCount int, lastSeen time.Time) CircuitFeatures {
	successRate := 0.0
	if o.Success {
		successRate = 1.0
	}

	return CircuitFeatures{
		LatencyNorm:   NormalizeLatency(o.LatencyMs),
		BandwidthNorm: NormalizeBandwidth(o.BandwidthKbps),
		SuccessRate:   successRate,
		TimeOfDay:     NormalizeTimeOfDay(o.Timestamp),
		SampleCount:   NormalizeSamples(sampleCount),
		Recency:       NormalizeRecency(lastSeen),
	}
}

// ComputeActualQuality computes the actual quality score from an observation
// This is the "ground truth" for training
func ComputeActualQuality(latencyMs, bandwidthKbps float64, success bool) float64 {
	if !success {
		return 0.0 // Failed = bad
	}

	// Weighted combination of latency and bandwidth
	latencyScore := NormalizeLatency(latencyMs)
	bandwidthScore := NormalizeBandwidth(bandwidthKbps)

	// Latency is more important for user experience (70% weight)
	return 0.7*latencyScore + 0.3*bandwidthScore
}

// ExitNodeStats tracks aggregated stats for an exit node
type ExitNodeStats struct {
	ExitNode         string    `json:"exit_node"`
	Country          string    `json:"country"`
	TotalSamples     int       `json:"total_samples"`
	SuccessCount     int       `json:"success_count"`
	LatencySum       float64   `json:"latency_sum"`
	BandwidthSum     float64   `json:"bandwidth_sum"`
	LastSeen         time.Time `json:"last_seen"`
	PredictedQuality float64   `json:"predicted_quality"` // From neural network
}

// SuccessRate returns the success rate
func (s *ExitNodeStats) SuccessRate() float64 {
	if s.TotalSamples == 0 {
		return 0.0
	}
	return float64(s.SuccessCount) / float64(s.TotalSamples)
}

// AvgLatency returns the average latency
func (s *ExitNodeStats) AvgLatency() float64 {
	if s.SuccessCount == 0 {
		return maxLatencyMs // Assume worst case
	}
	return s.LatencySum / float64(s.SuccessCount)
}

// AvgBandwidth returns the average bandwidth
func (s *ExitNodeStats) AvgBandwidth() float64 {
	if s.SuccessCount == 0 {
		return 0.0
	}
	return s.BandwidthSum / float64(s.SuccessCount)
}

// ToFeatures converts stats to normalized features
func (s *ExitNodeStats) ToFeatures() CircuitFeatures {
	return CircuitFeatures{
		LatencyNorm:   NormalizeLatency(s.AvgLatency()),
		BandwidthNorm: NormalizeBandwidth(s.AvgBandwidth()),
		SuccessRate:   s.SuccessRate(),
		TimeOfDay:     NormalizeTimeOfDay(time.Now()),
		SampleCount:   NormalizeSamples(s.TotalSamples),
		Recency:       NormalizeRecency(s.LastSeen),
	}
}

// Update updates stats with a new observation
func (s *ExitNodeStats) Update(obs CircuitObservation) {
	s.TotalSamples++
	s.LastSeen = obs.Timestamp
	if obs.Success {
		s.SuccessCount++
		s.LatencySum += obs.LatencyMs
		s.BandwidthSum += obs.BandwidthKbps
	}
}
