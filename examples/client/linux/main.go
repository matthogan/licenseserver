package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/matthogan/licenceserver/client/verifier"
)

//go:embed root-public-key.txt
var bootstrapRoot []byte

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: linux-client <licence.json>")
		os.Exit(2)
	}
	config, err := os.UserConfigDir() // normally $XDG_CONFIG_HOME or ~/.config
	check(err)
	store, err := verifier.OpenKeyringStore(filepath.Join(config, "example-app", "licensing", "keyring.json"), bootstrapRoot, verifier.StoreOptions{})
	check(err)
	client, err := store.Verifier(verifier.Options{ProductID: "com.example.test"})
	check(err)
	artifact, err := os.ReadFile(os.Args[1])
	check(err)
	licence, err := client.VerifyLicence(artifact)
	check(err)
	fmt.Printf("licence %s accepted; remote_execution=%t\n", licence.LicenceID, licence.Can("remote_execution"))
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "licensing error (%s): %v\n", verifier.CodeOf(err), err)
		os.Exit(1)
	}
}
