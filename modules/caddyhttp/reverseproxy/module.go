package reverseproxy

import (
	"fmt"

	"bitbucket.org/lightcodelabs/caddy2"
)

// Register caddy module.
func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.responders.reverse_proxy",
		New:  func() (interface{}, error) { return new(LoadBalanced), nil },
		OnLoad: func(instances []interface{}, _ interface{}) (interface{}, error) {
			// we don't need to do anything with prior state because healthcheckers are
			// cleaned up in OnUnload.
			s := &State{
				HealthCheckers: []*HealthChecker{},
			}

			for _, i := range instances {
				lb := i.(*LoadBalanced)

				err := NewLoadBalancedReverseProxy(lb, s)
				if err != nil {
					return nil, err
				}
			}

			return s, nil
		},
		OnUnload: func(state interface{}) error {
			s, ok := state.(*State)
			if !ok {
				return fmt.Errorf("proxy OnLoad: prior state not expected proxy.State type")
			}

			// cleanup old healthcheckers
			for _, hc := range s.HealthCheckers {
				hc.Stop()
			}

			return nil
		},
	})
}
