package ai

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestSmartCircuitSelector_GetExitRecommendations(t *testing.T) {
	// Create a temporary directory for test data
	tempDir, err := os.MkdirTemp("", "ai-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize selector
	selector := NewSmartCircuitSelector(tempDir)

	// Add some dummy performance data
	// We need enough samples to trigger recommendations (minSamples=5)
	for i := 0; i < 10; i++ {
		fp := fmt.Sprintf("%040d", i)
		selector.RecordCircuitPerformance(
			fp,
			"US",
			"example.com",
			float64(100+i*10), // increasing latency
			float64(1000-i*10), // decreasing bandwidth
			true,
		)
		// Record multiple times to reach minSamples
		for j := 0; j < 5; j++ {
			selector.RecordCircuitPerformance(
				fp,
				"US",
				"example.com",
				float64(100+i*10),
				float64(1000-i*10),
				true,
			)
		}
	}

	// Get recommendations
	rec := selector.GetExitRecommendations()
	if rec == nil {
		// Might return nil if confidence is too low or not enough data
		// But we added data. Let's check confidence logic.
		// Confidence = totalSamples / 250.0
		// We added 10 exits * 6 samples each = 60 samples.
		// Confidence = 60 / 250 = 0.24.
		// GetExitRecommendations returns nil if len(scores) < 3. We have 10 scores.
		// So it should return a recommendation, but with low confidence.
		t.Log("Rec is nil, likely low confidence but should not be nil if enough scores")
	} else {
		t.Logf("Rec: %+v", rec)
	}

	// Now let's try to trigger the race condition / concurrency issue
	// We need to simulate enough samples to reach high confidence (>= 1.0)
	// 250 samples needed.
	// Let's add more data.
	for i := 0; i < 10; i++ {
		fp := fmt.Sprintf("%040d", i)
		for j := 0; j < 30; j++ {
			selector.RecordCircuitPerformance(
				fp,
				"US",
				"example.com",
				float64(100+i*10),
				float64(1000-i*10),
				true,
			)
		}
	}

	// Now we have ~360 samples. Confidence should be > 1.0.

	// Call GetExitRecommendations multiple times concurrently
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rec := selector.GetExitRecommendations()
				if rec != nil {
					_ = len(rec.AvoidExits)
				}
				// Small sleep to allow context switches and real concurrent activity
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Also call RecordCircuitPerformance concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			fp := fmt.Sprintf("%040d", id)
			for j := 0; j < 50; j++ {
				selector.RecordCircuitPerformance(
					fp,
					"US",
					"example.com",
					150.0,
					800.0,
					true,
				)
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()
}
