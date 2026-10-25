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
		fmt.Fprintln(os.Stderr, "usage: windows-client <licence.json>")
		os.Exit(2)
	}
	config, err := os.UserConfigDir()
	check(err)
	store, err := verifier.OpenKeyringStore(filepath.Join(config, "ExampleApp", "licensing", "keyring.json"), bootstrapRoot, verifier.StoreOptions{})
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
