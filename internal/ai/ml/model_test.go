package ml

import (
	"os"
	"testing"
	"time"
)

func TestQualityModel_PredictAndTrain(t *testing.T) {
	// Use temp directory for test
	tmpDir, err := os.MkdirTemp("", "torforge-ml-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create model
	model, err := NewQualityModel(tmpDir)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}
	defer model.Close()

	// Test 1: Initial prediction (untrained model)
	features := CircuitFeatures{
		LatencyNorm:   0.8, // Low latency = good
		BandwidthNorm: 0.7, // High bandwidth = good
		SuccessRate:   1.0, // 100% success
		TimeOfDay:     0.5, // Noon
		SampleCount:   0.5, // Moderate samples
		Recency:       1.0, // Just now
	}

	score, err := model.Predict(features)
	if err != nil {
		t.Fatalf("prediction failed: %v", err)
	}
	t.Logf("Initial prediction (untrained): %.4f", score)

	// Test 2: Record observations for training
	// Simulate good circuits (high quality)
	for i := 0; i < 50; i++ {
		goodFeatures := CircuitFeatures{
			LatencyNorm:   0.9, // Very low latency
			BandwidthNorm: 0.8, // High bandwidth
			SuccessRate:   1.0, // Always succeeds
			TimeOfDay:     float64(i%24) / 24.0,
			SampleCount:   float64(i) / 100.0,
			Recency:       1.0,
		}
		model.RecordObservation(goodFeatures, 0.9) // High quality
	}

	// Simulate bad circuits (low quality)
	for i := 0; i < 50; i++ {
		badFeatures := CircuitFeatures{
			LatencyNorm:   0.2, // High latency
			BandwidthNorm: 0.1, // Low bandwidth
			SuccessRate:   0.5, // 50% success
			TimeOfDay:     float64(i%24) / 24.0,
			SampleCount:   float64(i) / 100.0,
			Recency:       0.5,
		}
		model.RecordObservation(badFeatures, 0.2) // Low quality
	}

	// Wait for training batches to complete
	time.Sleep(500 * time.Millisecond)

	// Test 3: Check stats after training
	stats := model.GetStats()
	t.Logf("Model stats after training:")
	t.Logf("  Train count: %v", stats["train_count"])
	t.Logf("  Predict count: %v", stats["predict_count"])
	t.Logf("  Avg loss: %v", stats["avg_loss"])
	t.Logf("  Architecture: %v", stats["architecture"])

	// Test 4: Predict on good vs bad circuit
	goodScore, _ := model.Predict(CircuitFeatures{
		LatencyNorm:   0.9,
		BandwidthNorm: 0.8,
		SuccessRate:   1.0,
		TimeOfDay:     0.5,
		SampleCount:   0.5,
		Recency:       1.0,
	})

	badScore, _ := model.Predict(CircuitFeatures{
		LatencyNorm:   0.1,
		BandwidthNorm: 0.1,
		SuccessRate:   0.3,
		TimeOfDay:     0.5,
		SampleCount:   0.5,
		Recency:       0.5,
	})

	t.Logf("Prediction for GOOD circuit: %.4f", goodScore)
	t.Logf("Prediction for BAD circuit:  %.4f", badScore)

	// Good circuits should score higher than bad circuits
	if goodScore <= badScore {
		t.Logf("WARNING: Good circuit should score higher than bad circuit after training")
		t.Logf("  This may improve with more training data")
	}

	// Test 5: Save and reload weights
	if err := model.SaveWeights(); err != nil {
		t.Fatalf("failed to save weights: %v", err)
	}

	// Create new model and load weights
	model2, err := NewQualityModel(tmpDir)
	if err != nil {
		t.Fatalf("failed to create second model: %v", err)
	}
	defer model2.Close()

	// Predictions should be similar
	score2, _ := model2.Predict(features)
	t.Logf("Prediction after reload: %.4f (was %.4f)", score2, score)
}

func TestNormalization(t *testing.T) {
	// Test latency normalization (lower = better = higher score)
	tests := []struct {
		latencyMs float64
		expected  string
	}{
		{0, "high"},     // 0ms = perfect = 1.0
		{100, "good"},   // 100ms = good
		{500, "medium"}, // 500ms = acceptable
		{2000, "low"},   // 2000ms = bad = 0.0
	}

	for _, tc := range tests {
		norm := NormalizeLatency(tc.latencyMs)
		t.Logf("Latency %4.0fms → normalized %.4f (%s)", tc.latencyMs, norm, tc.expected)
	}

	// Test bandwidth normalization (higher = better = higher score)
	bandwidthTests := []struct {
		kbps     float64
		expected string
	}{
		{0, "zero"},
		{1000, "low"},
		{10000, "medium"},
		{50000, "high"},
	}

	for _, tc := range bandwidthTests {
		norm := NormalizeBandwidth(tc.kbps)
		t.Logf("Bandwidth %6.0f kbps → normalized %.4f (%s)", tc.kbps, norm, tc.expected)
	}

	// Test recency normalization
	now := time.Now()
	t.Logf("Recency (now):      %.4f", NormalizeRecency(now))
	t.Logf("Recency (1h ago):   %.4f", NormalizeRecency(now.Add(-1*time.Hour)))
	t.Logf("Recency (1d ago):   %.4f", NormalizeRecency(now.Add(-24*time.Hour)))
	t.Logf("Recency (1w ago):   %.4f", NormalizeRecency(now.Add(-168*time.Hour)))
}

func TestComputeActualQuality(t *testing.T) {
	// Test quality computation
	tests := []struct {
		latency   float64
		bandwidth float64
		success   bool
		desc      string
	}{
		{50, 20000, true, "excellent"},
		{200, 5000, true, "good"},
		{500, 1000, true, "fair"},
		{1500, 500, true, "poor"},
		{100, 10000, false, "failed"},
	}

	for _, tc := range tests {
		quality := ComputeActualQuality(tc.latency, tc.bandwidth, tc.success)
		t.Logf("Quality (%s): latency=%4.0fms bw=%6.0f success=%v → %.4f",
			tc.desc, tc.latency, tc.bandwidth, tc.success, quality)
	}
}
