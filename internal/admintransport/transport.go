package admintransport

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

type ListenerConfig struct{ Transport, Address, SocketMode, PipeSDDL string }

func Listen(c ListenerConfig) (net.Listener, error) {
	switch c.Transport {
	case "tcp":
		return net.Listen("tcp", c.Address)
	case "unix":
		mode, err := strconv.ParseUint(c.SocketMode, 8, 32)
		if err != nil {
			return nil, err
		}
		return listenUnix(c.Address, uint32(mode))
	case "named_pipe":
		return listenPipe(c.Address, c.PipeSDDL)
	default:
		return nil, fmt.Errorf("unsupported admin transport %q", c.Transport)
	}
}

func DialContext(transport, address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		switch transport {
		case "unix":
			return dialUnix(ctx, address)
		case "named_pipe":
			return dialPipe(ctx, address)
		default:
			var d net.Dialer
			return d.DialContext(ctx, "tcp", address)
		}
	}
}

func ValidatePipeSDDL(sddl string) error { return validatePipeSDDL(sddl) }
