package security

import "fmt"

// UnsupportedAlgorithmError is a local capability limit, not a bad signature.
type UnsupportedAlgorithmError struct{ OID string }

func (e *UnsupportedAlgorithmError) Error() string {
	return fmt.Sprintf("unsupported curve OID: %s", e.OID)
}

// InvalidSignatureError is returned only after a supported verification operation
// has established that the signature does not match the signed bytes/key.
type InvalidSignatureError struct{}

func (*InvalidSignatureError) Error() string { return "cryptographic signature verification failed" }
