// Package ml implements a pure-Go neural network for exit node quality prediction.
//
// Architecture: 3-layer MLP (6 inputs → 16 hidden → 8 hidden → 1 output)
//
// Why pure Go? Security tools shouldn't depend on Python/TensorFlow:
//   - No additional attack surface from ML frameworks
//   - Single binary deployment (no pip, no CUDA, no version conflicts)
//   - Inference is fast enough (<1ms) for the problem size
//
// Why this architecture? The prediction problem is simple: given 6 normalized
// features (latency, bandwidth, success rate, time of day, sample count, recency),
// output a 0-1 quality score. Two hidden layers with 16/8 neurons handle
// non-linear patterns without overfitting on our small dataset (~250 samples).
package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
)

const (
	// Network architecture
	inputSize   = 6  // Features: latency, bandwidth, success_rate, time_of_day, samples, recency
	hiddenSize1 = 16 // First hidden layer
	hiddenSize2 = 8  // Second hidden layer
	outputSize  = 1  // Quality score

	// Learning parameters
	learningRate = 0.01
	batchSize    = 32
)

// CircuitFeatures represents input features for the neural network
type CircuitFeatures struct {
	LatencyNorm   float64 `json:"latency_norm"`   // Normalized latency (0-1, lower is better)
	BandwidthNorm float64 `json:"bandwidth_norm"` // Normalized bandwidth (0-1, higher is better)
	SuccessRate   float64 `json:"success_rate"`   // Success rate (0-1)
	TimeOfDay     float64 `json:"time_of_day"`    // Normalized hour (0-1)
	SampleCount   float64 `json:"sample_count"`   // Normalized sample count
	Recency       float64 `json:"recency"`        // How recent the data is (0-1, 1 = now)
}

// QualityModel is a pure-Go neural network for predicting circuit quality
// Architecture: 6 inputs → 16 hidden (ReLU) → 8 hidden (ReLU) → 1 output (Sigmoid)
type QualityModel struct {
	mu sync.RWMutex

	// Network weights and biases
	w1 [][]float64 // inputSize x hiddenSize1
	b1 []float64   // hiddenSize1
	w2 [][]float64 // hiddenSize1 x hiddenSize2
	b2 []float64   // hiddenSize2
	w3 [][]float64 // hiddenSize2 x outputSize
	b3 []float64   // outputSize

	// Training data buffer for mini-batch learning
	trainingBuffer []trainingExample
	bufferMu       sync.Mutex

	// Persistence
	dataDir   string
	modelFile string

	// Stats
	trainCount    int64
	predictCount  int64
	avgLoss       float64
	lastTrainTime time.Time
}

type trainingExample struct {
	features CircuitFeatures
	quality  float64
}

// NewQualityModel creates a new neural network model
func NewQualityModel(dataDir string) (*QualityModel, error) {
	log := logger.WithComponent("ml")

	m := &QualityModel{
		dataDir:        dataDir,
		modelFile:      filepath.Join(dataDir, "quality_model.json"),
		trainingBuffer: make([]trainingExample, 0, batchSize*2),
	}

	// Try to load existing weights
	if err := m.loadWeights(); err != nil {
		log.Debug().Err(err).Msg("no existing model, initializing random weights")
		m.initRandomWeights()
	} else {
		log.Info().Msg("loaded pre-trained model weights")
	}

	log.Info().
		Int("input", inputSize).
		Int("hidden1", hiddenSize1).
		Int("hidden2", hiddenSize2).
		Int("output", outputSize).
		Msg("🧠 Neural network model initialized (pure Go)")

	return m, nil
}

// initRandomWeights initializes weights with Xavier initialization
func (m *QualityModel) initRandomWeights() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Layer 1: input → hidden1
	m.w1 = make([][]float64, inputSize)
	limit1 := math.Sqrt(6.0 / float64(inputSize+hiddenSize1))
	for i := range m.w1 {
		m.w1[i] = make([]float64, hiddenSize1)
		for j := range m.w1[i] {
			m.w1[i][j] = (rng.Float64()*2 - 1) * limit1
		}
	}
	m.b1 = make([]float64, hiddenSize1)

	// Layer 2: hidden1 → hidden2
	m.w2 = make([][]float64, hiddenSize1)
	limit2 := math.Sqrt(6.0 / float64(hiddenSize1+hiddenSize2))
	for i := range m.w2 {
		m.w2[i] = make([]float64, hiddenSize2)
		for j := range m.w2[i] {
			m.w2[i][j] = (rng.Float64()*2 - 1) * limit2
		}
	}
	m.b2 = make([]float64, hiddenSize2)

	// Layer 3: hidden2 → output
	m.w3 = make([][]float64, hiddenSize2)
	limit3 := math.Sqrt(6.0 / float64(hiddenSize2+outputSize))
	for i := range m.w3 {
		m.w3[i] = make([]float64, outputSize)
		for j := range m.w3[i] {
			m.w3[i][j] = (rng.Float64()*2 - 1) * limit3
		}
	}
	m.b3 = make([]float64, outputSize)
}

// Activation functions
func relu(x float64) float64 {
	if x > 0 {
		return x
	}
	return 0
}

func reluDerivative(x float64) float64 {
	if x > 0 {
		return 1
	}
	return 0
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func sigmoidDerivative(x float64) float64 {
	s := sigmoid(x)
	return s * (1 - s)
}

// Predict predicts the quality score for given features
func (m *QualityModel) Predict(features CircuitFeatures) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Convert features to input array
	input := []float64{
		features.LatencyNorm,
		features.BandwidthNorm,
		features.SuccessRate,
		features.TimeOfDay,
		features.SampleCount,
		features.Recency,
	}

	// Forward pass
	output, _, _, _ := m.forward(input)
	atomic.AddInt64(&m.predictCount, 1)

	return output[0], nil
}

// forward performs forward pass through the network
func (m *QualityModel) forward(input []float64) (output []float64, h1 []float64, h2 []float64, z [][]float64) {
	// Layer 1: input → hidden1 (ReLU)
	z1 := make([]float64, hiddenSize1)
	h1 = make([]float64, hiddenSize1)
	for j := 0; j < hiddenSize1; j++ {
		sum := m.b1[j]
		for i := 0; i < inputSize; i++ {
			sum += input[i] * m.w1[i][j]
		}
		z1[j] = sum
		h1[j] = relu(sum)
	}

	// Layer 2: hidden1 → hidden2 (ReLU)
	z2 := make([]float64, hiddenSize2)
	h2 = make([]float64, hiddenSize2)
	for j := 0; j < hiddenSize2; j++ {
		sum := m.b2[j]
		for i := 0; i < hiddenSize1; i++ {
			sum += h1[i] * m.w2[i][j]
		}
		z2[j] = sum
		h2[j] = relu(sum)
	}

	// Layer 3: hidden2 → output (Sigmoid)
	z3 := make([]float64, outputSize)
	output = make([]float64, outputSize)
	for j := 0; j < outputSize; j++ {
		sum := m.b3[j]
		for i := 0; i < hiddenSize2; i++ {
			sum += h2[i] * m.w3[i][j]
		}
		z3[j] = sum
		output[j] = sigmoid(sum)
	}

	z = [][]float64{z1, z2, z3}
	return output, h1, h2, z
}

// RecordObservation records an observation for online learning
func (m *QualityModel) RecordObservation(features CircuitFeatures, actualQuality float64) {
	m.bufferMu.Lock()
	m.trainingBuffer = append(m.trainingBuffer, trainingExample{
		features: features,
		quality:  actualQuality,
	})

	// Train when buffer is full
	shouldTrain := len(m.trainingBuffer) >= batchSize
	m.bufferMu.Unlock()

	if shouldTrain {
		go m.trainBatch()
	}
}

// trainBatch performs mini-batch training with backpropagation
func (m *QualityModel) trainBatch() {
	m.bufferMu.Lock()
	if len(m.trainingBuffer) < batchSize {
		m.bufferMu.Unlock()
		return
	}

	// Take a batch
	batch := make([]trainingExample, batchSize)
	copy(batch, m.trainingBuffer[:batchSize])
	m.trainingBuffer = m.trainingBuffer[batchSize:]
	m.bufferMu.Unlock()

	log := logger.WithComponent("ml")
	totalLoss := 0.0

	m.mu.Lock()
	defer m.mu.Unlock()

	// Train on each example
	for _, example := range batch {
		input := []float64{
			example.features.LatencyNorm,
			example.features.BandwidthNorm,
			example.features.SuccessRate,
			example.features.TimeOfDay,
			example.features.SampleCount,
			example.features.Recency,
		}
		target := example.quality

		// Forward pass
		output, h1, h2, z := m.forward(input)

		// Compute loss (MSE)
		loss := math.Pow(output[0]-target, 2)
		totalLoss += loss

		// Backpropagation
		// Output layer delta
		d3 := make([]float64, outputSize)
		d3[0] = (output[0] - target) * sigmoidDerivative(z[2][0])

		// Hidden2 layer delta
		d2 := make([]float64, hiddenSize2)
		for i := 0; i < hiddenSize2; i++ {
			sum := 0.0
			for j := 0; j < outputSize; j++ {
				sum += d3[j] * m.w3[i][j]
			}
			d2[i] = sum * reluDerivative(z[1][i])
		}

		// Hidden1 layer delta
		d1 := make([]float64, hiddenSize1)
		for i := 0; i < hiddenSize1; i++ {
			sum := 0.0
			for j := 0; j < hiddenSize2; j++ {
				sum += d2[j] * m.w2[i][j]
			}
			d1[i] = sum * reluDerivative(z[0][i])
		}

		// Update weights and biases
		// Layer 3
		for i := 0; i < hiddenSize2; i++ {
			for j := 0; j < outputSize; j++ {
				m.w3[i][j] -= learningRate * d3[j] * h2[i]
			}
		}
		for j := 0; j < outputSize; j++ {
			m.b3[j] -= learningRate * d3[j]
		}

		// Layer 2
		for i := 0; i < hiddenSize1; i++ {
			for j := 0; j < hiddenSize2; j++ {
				m.w2[i][j] -= learningRate * d2[j] * h1[i]
			}
		}
		for j := 0; j < hiddenSize2; j++ {
			m.b2[j] -= learningRate * d2[j]
		}

		// Layer 1
		for i := 0; i < inputSize; i++ {
			for j := 0; j < hiddenSize1; j++ {
				m.w1[i][j] -= learningRate * d1[j] * input[i]
			}
		}
		for j := 0; j < hiddenSize1; j++ {
			m.b1[j] -= learningRate * d1[j]
		}

		m.trainCount++
	}

	// Update stats
	m.avgLoss = totalLoss / float64(batchSize)
	m.lastTrainTime = time.Now()

	// Save weights after each batch
	if err := m.saveWeightsLocked(); err != nil {
		log.Warn().Err(err).Msg("failed to save model weights")
	}

	log.Debug().
		Int64("train_count", m.trainCount).
		Float64("avg_loss", m.avgLoss).
		Msg("completed training batch")
}

// saveWeightsLocked saves model weights to disk (caller must hold lock)
func (m *QualityModel) saveWeightsLocked() error {
	data := map[string]interface{}{
		"w1":          m.w1,
		"b1":          m.b1,
		"w2":          m.w2,
		"b2":          m.b2,
		"w3":          m.w3,
		"b3":          m.b3,
		"train_count": m.trainCount,
		"avg_loss":    m.avgLoss,
		"saved_at":    time.Now(),
	}

	if err := os.MkdirAll(m.dataDir, 0700); err != nil {
		return err
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(m.modelFile, jsonData, 0600)
}

// loadWeights loads model weights from disk
func (m *QualityModel) loadWeights() error {
	data, err := os.ReadFile(m.modelFile)
	if err != nil {
		return err
	}

	var saved map[string]interface{}
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}

	// Parse weights - need to convert from interface{} to [][]float64
	if w, ok := saved["w1"].([]interface{}); ok {
		m.w1 = parseWeights2D(w)
	}
	if b, ok := saved["b1"].([]interface{}); ok {
		m.b1 = parseWeights1D(b)
	}
	if w, ok := saved["w2"].([]interface{}); ok {
		m.w2 = parseWeights2D(w)
	}
	if b, ok := saved["b2"].([]interface{}); ok {
		m.b2 = parseWeights1D(b)
	}
	if w, ok := saved["w3"].([]interface{}); ok {
		m.w3 = parseWeights2D(w)
	}
	if b, ok := saved["b3"].([]interface{}); ok {
		m.b3 = parseWeights1D(b)
	}

	// Validate dimensions
	if len(m.w1) != inputSize || len(m.w2) != hiddenSize1 || len(m.w3) != hiddenSize2 {
		return fmt.Errorf("invalid weight dimensions in saved model")
	}

	if tc, ok := saved["train_count"].(float64); ok {
		m.trainCount = int64(tc)
	}
	if al, ok := saved["avg_loss"].(float64); ok {
		m.avgLoss = al
	}

	return nil
}

func parseWeights2D(arr []interface{}) [][]float64 {
	result := make([][]float64, len(arr))
	for i, row := range arr {
		if rowSlice, ok := row.([]interface{}); ok {
			result[i] = parseWeights1D(rowSlice)
		}
	}
	return result
}

func parseWeights1D(arr []interface{}) []float64 {
	result := make([]float64, len(arr))
	for i, v := range arr {
		if f, ok := v.(float64); ok {
			result[i] = f
		}
	}
	return result
}

// GetStats returns model statistics
func (m *QualityModel) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"train_count":     m.trainCount,
		"predict_count":   atomic.LoadInt64(&m.predictCount),
		"avg_loss":        m.avgLoss,
		"last_train_time": m.lastTrainTime,
		"architecture":    fmt.Sprintf("%d→%d→%d→%d", inputSize, hiddenSize1, hiddenSize2, outputSize),
		"buffer_size":     len(m.trainingBuffer),
		"implementation":  "pure-go",
	}
}

// SaveWeights saves the current model weights
func (m *QualityModel) SaveWeights() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveWeightsLocked()
}

// Close cleans up resources
func (m *QualityModel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveWeightsLocked()
}
