//go:build windows

package admintransport

import (
	"context"
	"errors"
	"net"

	"github.com/Microsoft/go-winio"
)

func listenUnix(string, uint32) (net.Listener, error) {
	return nil, errors.New("Unix sockets are not supported on Windows")
}
func dialUnix(context.Context, string) (net.Conn, error) {
	return nil, errors.New("Unix sockets are not supported on Windows")
}
func listenPipe(name, sddl string) (net.Listener, error) {
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl, MessageMode: false, InputBufferSize: 64 * 1024, OutputBufferSize: 64 * 1024})
}
func dialPipe(ctx context.Context, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, name)
}
func validatePipeSDDL(sddl string) error { _, err := winio.SddlToSecurityDescriptor(sddl); return err }
