package verifier

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable, machine-readable verification outcome suitable for
// mapping to desktop UI states. Programs should branch on CodeOf, not text.
type ErrorCode string

const (
	CodeMalformed          ErrorCode = "malformed"
	CodeTooLarge           ErrorCode = "too_large"
	CodeInvalidSignature   ErrorCode = "invalid_signature"
	CodeUntrustedRoot      ErrorCode = "untrusted_root"
	CodeIssuerUnauthorized ErrorCode = "issuer_unauthorized"
	CodeWrongProduct       ErrorCode = "wrong_product"
	CodeNotYetValid        ErrorCode = "not_yet_valid"
	CodeExpired            ErrorCode = "expired"
	CodeTransitionInactive ErrorCode = "transition_inactive"
	CodeTransitionExpired  ErrorCode = "transition_expired"
	CodeStateConflict      ErrorCode = "state_conflict"
	CodePersistence        ErrorCode = "persistence"
)

// Error is the package's typed error. Detail is safe for logs and contains no
// licence payload or key material. Code is the stable desktop-facing value.
type Error struct {
	Code      ErrorCode
	Operation string
	Detail    string
	cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s: %s", e.Operation, e.Code, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Code)
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.Code == t.Code
}

var (
	ErrMalformed          = &Error{Code: CodeMalformed}
	ErrTooLarge           = &Error{Code: CodeTooLarge}
	ErrInvalidSignature   = &Error{Code: CodeInvalidSignature}
	ErrUntrustedRoot      = &Error{Code: CodeUntrustedRoot}
	ErrIssuerUnauthorized = &Error{Code: CodeIssuerUnauthorized}
	ErrWrongProduct       = &Error{Code: CodeWrongProduct}
	ErrNotYetValid        = &Error{Code: CodeNotYetValid}
	ErrExpired            = &Error{Code: CodeExpired}
	ErrTransitionInactive = &Error{Code: CodeTransitionInactive}
	ErrTransitionExpired  = &Error{Code: CodeTransitionExpired}
	ErrStateConflict      = &Error{Code: CodeStateConflict}
	ErrPersistence        = &Error{Code: CodePersistence}
)

// CodeOf returns a stable code for a verifier error. An unknown error returns
// the empty code so callers do not accidentally classify unrelated failures.
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

func fail(code ErrorCode, operation, detail string, cause error) error {
	return &Error{Code: code, Operation: operation, Detail: detail, cause: cause}
}
