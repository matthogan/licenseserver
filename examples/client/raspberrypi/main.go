package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/matthogan/licenceserver/client/verifier"
)

//go:embed root-public-key.txt
var bootstrapRoot []byte

func main() {
	licencePath := os.Getenv("EXAMPLE_LICENCE_PATH")
	if licencePath == "" {
		licencePath = "/var/lib/example-app/licence.json"
	}
	// Create /var/lib/example-app as the unprivileged service user during
	// installation; the verifier creates the licensing child with mode 0700.
	store, err := verifier.OpenKeyringStore("/var/lib/example-app/licensing/keyring.json", bootstrapRoot, verifier.StoreOptions{})
	check(err)
	client, err := store.Verifier(verifier.Options{ProductID: "com.example.test"})
	check(err)
	artifact, err := os.ReadFile(licencePath)
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
