# Client examples

These are minimal compilable integrations for Windows, Linux desktop, and a
Raspberry Pi system service. Their embedded root is the public test-vector
root and is **not a production trust anchor**. Replace each
`root-public-key.txt` during product build/release with the offline production
root obtained through your controlled build secret/input process.

The examples intentionally keep acquisition and UI policy out of the verifier.
They open an OS-appropriate keyring, bind verification to one product ID, and
authorize a named capability from a successfully verified licence.
