package verifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

func decodeStrict(data []byte, maximum int, destination any, operation string) error {
	if len(data) == 0 {
		return fail(CodeMalformed, operation, "empty JSON", nil)
	}
	if len(data) > maximum {
		return fail(CodeTooLarge, operation, "input exceeds parsing limit", nil)
	}
	if !utf8.Valid(data) {
		return fail(CodeMalformed, operation, "JSON is not valid UTF-8", nil)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return fail(CodeMalformed, operation, "invalid JSON structure", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fail(CodeMalformed, operation, "invalid JSON", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fail(CodeMalformed, operation, "trailing JSON data", err)
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var tokens int
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return fmt.Errorf("JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		tokens++
		if tokens > 4096 {
			return fmt.Errorf("JSON token count exceeds limit")
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				name, ok := nameToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, duplicate := seen[name]; duplicate {
					return fmt.Errorf("duplicate object key")
				}
				seen[name] = struct{}{}
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter")
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
