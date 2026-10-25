package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	if path := os.Getenv("FAKE_LITESTREAM_LOG"); path != "" {
		f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if f != nil {
			fmt.Fprintln(f, os.Args[1:])
			_ = f.Close()
		}
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("litestream v0.5.15")
	case "replicate":
		if has("-once") {
			return
		}
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
	case "ltx":
		_ = json.NewEncoder(os.Stdout).Encode([]map[string]any{{"level": 0, "min_txid": "0000000000000001", "max_txid": "0000000000000002", "size": 4096, "timestamp": time.Now().UTC()}})
	case "status":
		_ = json.NewEncoder(os.Stdout).Encode([]map[string]any{{"database": "source.db", "status": "ok", "local_txid": "0000000000000002", "wal_size": "0 B"}})
	case "databases":
		_ = json.NewEncoder(os.Stdout).Encode([]map[string]any{{"path": "source.db", "replica": "s3://bucket/path"}})
	case "restore":
		if has("-dry-run") {
			fmt.Println(`{"source":"configured","target_path":"planned.db","replica":"s3","min_txid":"0000000000000001","max_txid":"0000000000000002","files":[]}`)
			return
		}
		output := value("-o")
		source := os.Getenv("FAKE_LITESTREAM_SOURCE")
		in, err := os.Open(source)
		must(err)
		defer in.Close()
		must(os.MkdirAll(filepath.Dir(output), 0o750))
		out, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		must(err)
		_, err = io.Copy(out, in)
		must(err)
		must(out.Close())
		fmt.Println(`{"status":"restored"}`)
	default:
		os.Exit(2)
	}
}

func has(flag string) bool {
	for _, arg := range os.Args {
		if arg == flag {
			return true
		}
	}
	return false
}
func value(flag string) string {
	for i, arg := range os.Args {
		if arg == flag && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
