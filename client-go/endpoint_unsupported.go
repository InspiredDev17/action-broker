//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package actionbroker

import "fmt"

type endpointIdentity struct{}

func inspectSocketEndpoint(string, uint32) (endpointIdentity, error) {
	return endpointIdentity{}, fmt.Errorf("secure Unix socket identity checks are unsupported on this operating system")
}

func confirmSocketEndpoint(string, uint32, endpointIdentity) error {
	return fmt.Errorf("secure Unix socket identity checks are unsupported on this operating system")
}
