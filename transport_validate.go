package noise

import (
	"github.com/samber/oops"
)

// validateNetworkAddr validates the network and address parameters shared
// by validateDialParams and validateListenParams.
func validateNetworkAddr(network, addr string) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			Errorf("network cannot be empty")
	}

	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			Errorf("address cannot be empty")
	}

	return nil
}

// validateDialParams validates parameters for DialNoise function.
func validateDialParams(network, addr string, config *ConnConfig) error {
	if err := validateNetworkAddr(network, addr); err != nil {
		return err
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}

// validateListenParams validates parameters for ListenNoise function.
func validateListenParams(network, addr string, config *ListenerConfig) error {
	if err := validateNetworkAddr(network, addr); err != nil {
		return err
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}
