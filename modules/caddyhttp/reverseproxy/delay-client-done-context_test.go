package reverseproxy

import (
	"context"
	"testing"
	"time"
)

func TestDelayClientDoneContext(t *testing.T) {
	// Helper function to test context cancellation behavior
	testContextCancellation := func(t *testing.T, ctx context.Context, parentDone <-chan struct{}, shouldCloseDoneBeforeRoundTrip bool, shouldCloseDoneAfterRoundTrip bool) {

		d := NewDelayClientDoneContext(ctx, parentDone)

		select {
		case <-d.Done():
			if !shouldCloseDoneBeforeRoundTrip {
				t.Errorf("Expected done channel to not be closed before round trip")
			}
		case <-time.After(25 * time.Millisecond):
			if shouldCloseDoneBeforeRoundTrip {
				t.Errorf("Expected done channel to be closed before round trip")
			}
		}

		time.Sleep(50 * time.Millisecond)
		d.RoundTripDone()

		select {
		case <-d.Done():
			if !shouldCloseDoneAfterRoundTrip {
				t.Errorf("Expected done channel to not be closed after round trip")
			}
		case <-time.After(25 * time.Millisecond):
			if shouldCloseDoneAfterRoundTrip {
				t.Errorf("Expected done channel to be closed after round trip")
			}
		}
	}

	t.Run("Test with parent context done", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create a parent context and cancel it
		parentCtx, parentCancel := context.WithCancel(context.Background())
		parentCancel()

		// Test that the done channel closes immediately
		testContextCancellation(t, ctx, parentCtx.Done(), true, true)
	})

	t.Run("Test with context done before round trip", func(t *testing.T) {
		// Create a context and cancel it immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Test that the done channel closes after the round trip
		testContextCancellation(t, ctx, nil, false, true)
	})

	t.Run("Test with round trip completion", func(t *testing.T) {
		// Create a context with a parent
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Run the test and no done channel should be closed
		testContextCancellation(t, ctx, make(chan struct{}), false, false)
	})

	t.Run("Test with round trip done and then context cancel", func(t *testing.T) {
		// Create a context
		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		// Test that the done channel closes when the round trip completes
		testContextCancellation(t, ctx, nil, false, true)
	})

	t.Run("Test round trip done before parent context done", func(t *testing.T) {
		// Create a context
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		parentDone := make(chan struct{})

		go func() {
			time.Sleep(50 * time.Millisecond)
			close(parentDone)
		}()

		// Test that the done channel closes when the round trip completes
		testContextCancellation(t, ctx, parentDone, false, true)
	})
}
