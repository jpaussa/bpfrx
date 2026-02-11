package dhcprelay

import "golang.org/x/sys/unix"

// setBindToDevice sets SO_BINDTODEVICE on the given file descriptor.
func setBindToDevice(fd uintptr, ifaceName string) error {
	return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
}
