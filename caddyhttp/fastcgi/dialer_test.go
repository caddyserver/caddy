package fastcgi

import (
	"errors"
	"testing"
)

func TestLoadbalancingDialer(t *testing.T) {
	// given
	runs := 100
	mockDialer1 := new(mockDialer)
	mockDialer2 := new(mockDialer)

	dialer := &loadBalancingDialer{dialers: []dialer{mockDialer1, mockDialer2}}

	// when
	for i := 0; i < runs; i++ {
		client, err := dialer.Dial()
		dialer.Close(client)

		if err != nil {
			t.Errorf("Expected error to be nil")
		}
	}

	// then
	if mockDialer1.dialCalled != mockDialer2.dialCalled && mockDialer1.dialCalled != 50 {
		t.Errorf("Expected dialer to call Dial() on multiple backend dialers %d times [actual: %d, %d]", 50, mockDialer1.dialCalled, mockDialer2.dialCalled)
	}

	if mockDialer1.closeCalled != mockDialer2.closeCalled && mockDialer1.closeCalled != 50 {
		t.Errorf("Expected dialer to call Close() on multiple backend dialers %d times [actual: %d, %d]", 50, mockDialer1.closeCalled, mockDialer2.closeCalled)
	}
}

func TestLoadBalancingDialerShouldReturnDialerAwareClient(t *testing.T) {
	// given
	mockDialer1 := new(mockDialer)
	dialer := &loadBalancingDialer{dialers: []dialer{mockDialer1}}

	// when
	client, err := dialer.Dial()

	// then
	if err != nil {
		t.Errorf("Expected error to be nil")
	}

	if awareClient, ok := client.(*dialerAwareClient); !ok {
		t.Error("Expected dialer to wrap client")
	} else {
		if awareClient.dialer != mockDialer1 {
			t.Error("Expected wrapped client to have reference to dialer")
		}
	}
}

func TestLoadBalancingDialerShouldUnderlyingReturnDialerError(t *testing.T) {
	// given
	mockDialer1 := new(errorReturningDialer)
	dialer := &loadBalancingDialer{dialers: []dialer{mockDialer1}}

	// when
	_, err := dialer.Dial()

	// then
	if err.Error() != "Error during dial" {
		t.Errorf("Expected 'Error during dial', got: '%s'", err.Error())
	}
}

func TestLoadBalancingDialerShouldCloseClient(t *testing.T) {
	// given
	mockDialer1 := new(mockDialer)
	mockDialer2 := new(mockDialer)

	dialer := &loadBalancingDialer{dialers: []dialer{mockDialer1, mockDialer2}}
	client, _ := dialer.Dial()

	// when
	err := dialer.Close(client)

	// then
	if err != nil {
		t.Error("Expected error not to occur")
	}

	// load balancing starts from index 1
	if mockDialer2.client != client {
		t.Errorf("Expected Close() to be called on referenced dialer")
	}
}

type mockDialer struct {
	dialCalled  int
	closeCalled int
	client      Client
}

type mockClient struct {
	Client
}

func (m *mockDialer) Dial() (Client, error) {
	m.dialCalled++
	return mockClient{Client: &FCGIClient{}}, nil
}

func (m *mockDialer) Close(c Client) error {
	m.client = c
	m.closeCalled++
	return nil
}

type errorReturningDialer struct {
	client Client
}

func (m *errorReturningDialer) Dial() (Client, error) {
	return mockClient{Client: &FCGIClient{}}, errors.New("Error during dial")
}

func (m *errorReturningDialer) Close(c Client) error {
	m.client = c
	return errors.New("Error during close")
}
