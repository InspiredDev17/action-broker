//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package actionbroker

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type endpointIdentity struct {
	device uint64
	inode  uint64
	owner  uint32
	group  uint32
}

func inspectSocketEndpoint(socketPath string, expectedBrokerUID uint32) (endpointIdentity, error) {
	clean := filepath.Clean(socketPath)
	if clean != socketPath {
		return endpointIdentity{}, fmt.Errorf("socket path is not canonical")
	}
	parent := filepath.Dir(clean)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("could not resolve socket parent: %w", err)
	}
	if resolvedParent != parent {
		return endpointIdentity{}, fmt.Errorf("socket parent contains a symbolic link")
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("could not inspect socket parent: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return endpointIdentity{}, fmt.Errorf("socket parent is not a real directory")
	}
	if parentInfo.Mode().Perm()&0o027 != 0 {
		return endpointIdentity{}, fmt.Errorf("socket parent permits group write or other access")
	}
	parentOwner, parentGroup, err := requireExpectedOwner(parentInfo, expectedBrokerUID)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("socket parent ownership is invalid: %w", err)
	}
	identity, err := inspectSocketFile(clean, expectedBrokerUID)
	if err != nil {
		return endpointIdentity{}, err
	}
	if identity.owner != parentOwner || identity.group != parentGroup {
		return endpointIdentity{}, fmt.Errorf("socket and parent owner or group differ")
	}
	return identity, nil
}

func confirmSocketEndpoint(socketPath string, expectedBrokerUID uint32, expected endpointIdentity) error {
	actual, err := inspectSocketFile(socketPath, expectedBrokerUID)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("socket device or inode changed")
	}
	return nil
}

func inspectSocketFile(socketPath string, expectedBrokerUID uint32) (endpointIdentity, error) {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("could not inspect socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return endpointIdentity{}, fmt.Errorf("endpoint is not a Unix socket")
	}
	if info.Mode().Perm()&0o117 != 0 {
		return endpointIdentity{}, fmt.Errorf("socket permits execute or other access")
	}
	owner, group, err := requireExpectedOwner(info, expectedBrokerUID)
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("socket ownership is invalid: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return endpointIdentity{}, fmt.Errorf("socket filesystem identity is unavailable")
	}
	return endpointIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), owner: owner, group: group}, nil
}

func requireExpectedOwner(info os.FileInfo, expectedBrokerUID uint32) (uint32, uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("filesystem owner is unavailable")
	}
	if uint64(stat.Uid) != uint64(expectedBrokerUID) {
		return 0, 0, fmt.Errorf("filesystem object is not owned by the configured broker UID")
	}
	return uint32(stat.Uid), uint32(stat.Gid), nil
}
