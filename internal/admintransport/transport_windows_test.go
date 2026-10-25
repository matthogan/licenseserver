//go:build windows

package admintransport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWindowsNamedPipeHTTP(t *testing.T) {
	name := `\\.\pipe\licd-test-` + uuid.NewString()
	listener, err := Listen(ListenerConfig{Transport: "named_pipe", Address: name, PipeSDDL: "D:P(A;;GA;;;WD)"})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })}
	defer server.Shutdown(context.Background())
	go server.Serve(listener)
	transport := &http.Transport{DialContext: DialContext("named_pipe", name)}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get("http://licd/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q", body)
	}
}
