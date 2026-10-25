package dataexport

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/domain"
)

const (
	maxFieldLength       = 512
	maxArchiveEntryBytes = 256 << 20
	maxArchiveBytes      = 1 << 30
)

var recordFileNames = []string{"activations.ndjson", "audit-events.ndjson", "licences.ndjson", "revocations.ndjson"}

func ValidateFilter(filter exportdata.Filter) error {
	if len(filter.ProductID) > 256 || len(filter.LicenceID) > 256 || len(filter.CustomerRef) > maxFieldLength || len(filter.Status) > 64 ||
		strings.ContainsAny(filter.ProductID+filter.LicenceID+filter.CustomerRef+filter.Status, "\x00\r\n") {
		return domain.ErrInvalid
	}
	if filter.Status != "" && filter.Status != "active" && filter.Status != "revoked" {
		return domain.ErrInvalid
	}
	if filter.From != nil && filter.From.IsZero() || filter.To != nil && filter.To.IsZero() || filter.From != nil && filter.To != nil && !filter.From.Before(*filter.To) {
		return domain.ErrInvalid
	}
	return nil
}

// WriteArchive creates a deterministic gzip/POSIX-tar bundle. Record order,
// file order, JSON field order and checksum order are stable.
func WriteArchive(ctx context.Context, repo domain.Repository, filter exportdata.Filter, createdAt time.Time, destination io.Writer) (exportdata.Manifest, error) {
	var empty exportdata.Manifest
	if repo == nil || destination == nil || createdAt.IsZero() || ValidateFilter(filter) != nil {
		return empty, domain.ErrInvalid
	}
	filter = normalizedFilter(filter)
	snapshot, err := repo.QueryDataExport(ctx, domain.DataExportFilter{ProductID: filter.ProductID, LicenceID: filter.LicenceID, CustomerRef: filter.CustomerRef, Status: filter.Status, From: filter.From, To: filter.To})
	if err != nil {
		return empty, err
	}
	bundle, err := project(snapshot)
	if err != nil {
		return empty, err
	}
	temporary, err := os.MkdirTemp("", "licd-public-data-export-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(temporary)

	files := make([]exportdata.File, 0, len(recordFileNames))
	if file, writeErr := writeNDJSON(filepath.Join(temporary, "licences.ndjson"), bundle.Licences); writeErr != nil {
		return empty, writeErr
	} else {
		files = append(files, file)
	}
	if file, writeErr := writeNDJSON(filepath.Join(temporary, "activations.ndjson"), bundle.Activations); writeErr != nil {
		return empty, writeErr
	} else {
		files = append(files, file)
	}
	if file, writeErr := writeNDJSON(filepath.Join(temporary, "revocations.ndjson"), bundle.Revocations); writeErr != nil {
		return empty, writeErr
	} else {
		files = append(files, file)
	}
	if file, writeErr := writeNDJSON(filepath.Join(temporary, "audit-events.ndjson"), bundle.AuditEvents); writeErr != nil {
		return empty, writeErr
	} else {
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	manifest := exportdata.Manifest{
		SchemaVersion: exportdata.SchemaVersion,
		Format:        exportdata.FormatName,
		FormatVersion: exportdata.FormatVersion,
		CreatedAt:     createdAt.UTC(),
		Filters:       filter,
		RecordCounts: exportdata.RecordCounts{
			Licences: len(bundle.Licences), Activations: len(bundle.Activations),
			Revocations: len(bundle.Revocations), AuditEvents: len(bundle.AuditEvents),
		},
		Files:          files,
		TimeSemantics:  "half-open [from,to), applied to each record occurrence time",
		PrivacyProfile: "public-v1: no private keys, secrets, trial subject hashes, activation HMACs, or raw activation codes",
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return empty, err
	}
	manifestData = append(manifestData, '\n')
	if err = writeExclusive(filepath.Join(temporary, "manifest.json"), manifestData); err != nil {
		return empty, err
	}
	checksumNames := append(append([]string(nil), recordFileNames...), "manifest.json")
	sort.Strings(checksumNames)
	var checksums strings.Builder
	for _, name := range checksumNames {
		data, readErr := os.ReadFile(filepath.Join(temporary, name))
		if readErr != nil {
			return empty, readErr
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&checksums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	if err = writeExclusive(filepath.Join(temporary, "checksums.sha256"), []byte(checksums.String())); err != nil {
		return empty, err
	}
	if err = writeTarGzip(temporary, destination); err != nil {
		return empty, err
	}
	return manifest, nil
}

func project(snapshot domain.DataExportSnapshot) (exportdata.Bundle, error) {
	var bundle exportdata.Bundle
	for _, source := range snapshot.Licences {
		if !json.Valid(source.SignedArtifact) || len(source.Metadata) > 0 && !json.Valid(source.Metadata) {
			return bundle, fmt.Errorf("licence %s contains invalid stored JSON", source.LicenceID)
		}
		metadata, err := sanitizedJSON(source.Metadata)
		if err != nil {
			return bundle, fmt.Errorf("sanitize licence %s metadata: %w", source.LicenceID, err)
		}
		bundle.Licences = append(bundle.Licences, exportdata.Licence{
			SchemaVersion: exportdata.SchemaVersion, LicenceID: source.LicenceID, ProductID: source.ProductID,
			LicenceType: source.LicenceType, CustomerRef: source.CustomerRef, PurchaseRef: source.PurchaseRef,
			IssuerKeyID: source.IssuerKeyID, IssuedAt: source.IssuedAt, NotBefore: source.NotBefore,
			ExpiresAt: source.ExpiresAt, Status: source.Status, PayloadSHA256: hex.EncodeToString(source.PayloadHash),
			SignedLicenceArtifact: cloneJSON(source.SignedArtifact), Metadata: metadata, CreatedAt: source.CreatedAt,
		})
	}
	for _, source := range snapshot.Activations {
		if len(source.Metadata) > 0 && !json.Valid(source.Metadata) {
			return bundle, fmt.Errorf("activation %s contains invalid stored metadata", source.ActivationID)
		}
		metadata, err := sanitizedJSON(source.Metadata)
		if err != nil {
			return bundle, fmt.Errorf("sanitize activation %s metadata: %w", source.ActivationID, err)
		}
		bundle.Activations = append(bundle.Activations, exportdata.Activation{
			SchemaVersion: exportdata.SchemaVersion, ActivationID: source.ActivationID,
			ActivationCodeID: source.ActivationCodeID, LicenceID: source.LicenceID,
			ActivatedAt: source.ActivatedAt, LastRetrievedAt: source.LastRetrievedAt,
			RevokedAt: source.RevokedAt, RevocationReason: source.RevocationReason, Metadata: metadata,
		})
	}
	for _, source := range snapshot.Revocations {
		bundle.Revocations = append(bundle.Revocations, exportdata.Revocation{
			SchemaVersion: exportdata.SchemaVersion, RevocationID: source.RevocationID,
			LicenceID: source.LicenceID, ReasonCode: source.ReasonCode, ReasonText: source.ReasonText, RevokedAt: source.RevokedAt,
		})
	}
	for _, source := range snapshot.AuditEvents {
		details := sanitizedDetails(source.Event)
		bundle.AuditEvents = append(bundle.AuditEvents, exportdata.AuditEvent{
			SchemaVersion: exportdata.SchemaVersion, EventID: source.EventID, OccurredAt: source.OccurredAt,
			ActorType: source.ActorType, ActorRef: source.ActorRef, EventType: source.EventType,
			AggregateType: source.AggregateType, AggregateID: source.AggregateID, RequestID: source.RequestID, Details: details,
		})
	}
	return bundle, nil
}

func normalizedFilter(filter exportdata.Filter) exportdata.Filter {
	filter.ProductID = strings.TrimSpace(filter.ProductID)
	filter.LicenceID = strings.TrimSpace(filter.LicenceID)
	filter.CustomerRef = strings.TrimSpace(filter.CustomerRef)
	filter.Status = strings.TrimSpace(filter.Status)
	if filter.From != nil {
		value := filter.From.UTC()
		filter.From = &value
	}
	if filter.To != nil {
		value := filter.To.UTC()
		filter.To = &value
	}
	return filter
}

func sanitizedDetails(raw json.RawMessage) map[string]any {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	clean, _ := sanitize(value).(map[string]any)
	return clean
}

func sanitizedJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sanitize(value))
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func sanitize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(typed))
		for key, child := range typed {
			if sensitiveKey(key) {
				continue
			}
			clean[key] = sanitize(child)
		}
		return clean
	case []any:
		clean := make([]any, len(typed))
		for i := range typed {
			clean[i] = sanitize(typed[i])
		}
		return clean
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	return normalized == "code" || normalized == "secret" || normalized == "password" || normalized == "token" ||
		normalized == "authorization" || normalized == "cookie" || strings.Contains(normalized, "credential") ||
		strings.Contains(normalized, "private_key") || strings.Contains(normalized, "access_key") || strings.Contains(normalized, "api_key") ||
		strings.Contains(normalized, "hmac") || strings.HasSuffix(normalized, "_secret") || strings.HasSuffix(normalized, "_password") || strings.HasSuffix(normalized, "_token") ||
		strings.HasSuffix(normalized, "_hash") && normalized != "payload_hash" || strings.HasSuffix(normalized, "_digest")
}

func cloneJSON(source json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), source...)
}

func writeNDJSON[T any](path string, records []T) (exportdata.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return exportdata.File{}, err
	}
	hash := sha256.New()
	written := int64(0)
	writer := io.MultiWriter(file, hash, countWriter{&written})
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if err = encoder.Encode(record); err != nil {
			file.Close()
			return exportdata.File{}, err
		}
	}
	if err = file.Sync(); err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		return exportdata.File{}, err
	}
	return exportdata.File{Name: filepath.Base(path), SHA256: hex.EncodeToString(hash.Sum(nil)), SizeBytes: written, RecordCount: len(records)}, nil
}

type countWriter struct{ count *int64 }

func (w countWriter) Write(data []byte) (int, error) {
	*w.count += int64(len(data))
	return len(data), nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func writeTarGzip(directory string, destination io.Writer) error {
	gzipWriter, err := gzip.NewWriterLevel(destination, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected export entry %s", entry.Name())
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		header := &tar.Header{Name: entry.Name(), Mode: 0o640, Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err = tarWriter.WriteHeader(header); err != nil {
			return err
		}
		file, openErr := os.Open(filepath.Join(directory, entry.Name()))
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

// ReadArchive validates checksums, schemas, record counts, file names and
// parsing limits, returning a decoded migration-friendly bundle.
func ReadArchive(source io.Reader) (exportdata.Bundle, error) {
	var bundle exportdata.Bundle
	gzipReader, err := gzip.NewReader(io.LimitReader(source, maxArchiveBytes+1))
	if err != nil {
		return bundle, err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	total := int64(0)
	allowed := map[string]bool{"activations.ndjson": true, "audit-events.ndjson": true, "checksums.sha256": true, "licences.ndjson": true, "manifest.json": true, "revocations.ndjson": true}
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return bundle, nextErr
		}
		if !allowed[header.Name] || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxArchiveEntryBytes {
			return bundle, fmt.Errorf("invalid data export entry %q", header.Name)
		}
		if _, duplicate := files[header.Name]; duplicate {
			return bundle, fmt.Errorf("duplicate data export entry %q", header.Name)
		}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil || int64(len(data)) != header.Size {
			return bundle, fmt.Errorf("read data export entry %q: %w", header.Name, readErr)
		}
		total += int64(len(data))
		if total > maxArchiveBytes {
			return bundle, fmt.Errorf("data export expands beyond limit")
		}
		files[header.Name] = data
	}
	if len(files) != len(allowed) {
		return bundle, fmt.Errorf("data export is missing required files")
	}
	if err = verifyChecksums(files); err != nil {
		return bundle, err
	}
	if err = decodeSingleJSON(files["manifest.json"], &bundle.Manifest); err != nil {
		return bundle, fmt.Errorf("manifest: %w", err)
	}
	if bundle.Manifest.SchemaVersion != exportdata.SchemaVersion || bundle.Manifest.Format != exportdata.FormatName || bundle.Manifest.FormatVersion != exportdata.FormatVersion {
		return bundle, fmt.Errorf("unsupported data export schema or format")
	}
	if err = decodeNDJSON(files["licences.ndjson"], &bundle.Licences); err != nil {
		return bundle, fmt.Errorf("licences: %w", err)
	}
	if err = decodeNDJSON(files["activations.ndjson"], &bundle.Activations); err != nil {
		return bundle, fmt.Errorf("activations: %w", err)
	}
	if err = decodeNDJSON(files["revocations.ndjson"], &bundle.Revocations); err != nil {
		return bundle, fmt.Errorf("revocations: %w", err)
	}
	if err = decodeNDJSON(files["audit-events.ndjson"], &bundle.AuditEvents); err != nil {
		return bundle, fmt.Errorf("audit events: %w", err)
	}
	counts := bundle.Manifest.RecordCounts
	if counts.Licences != len(bundle.Licences) || counts.Activations != len(bundle.Activations) || counts.Revocations != len(bundle.Revocations) || counts.AuditEvents != len(bundle.AuditEvents) {
		return bundle, fmt.Errorf("manifest record counts do not match datasets")
	}
	countByName := map[string]int{
		"licences.ndjson": len(bundle.Licences), "activations.ndjson": len(bundle.Activations),
		"revocations.ndjson": len(bundle.Revocations), "audit-events.ndjson": len(bundle.AuditEvents),
	}
	if len(bundle.Manifest.Files) != len(countByName) {
		return bundle, fmt.Errorf("manifest file catalogue is incomplete")
	}
	seenManifestFile := make(map[string]bool, len(countByName))
	for _, descriptor := range bundle.Manifest.Files {
		data, exists := files[descriptor.Name]
		if !exists || descriptor.Name == "manifest.json" || descriptor.Name == "checksums.sha256" || seenManifestFile[descriptor.Name] {
			return bundle, fmt.Errorf("invalid manifest file descriptor %q", descriptor.Name)
		}
		sum := sha256.Sum256(data)
		if descriptor.SizeBytes != int64(len(data)) || descriptor.RecordCount != countByName[descriptor.Name] || !strings.EqualFold(descriptor.SHA256, hex.EncodeToString(sum[:])) {
			return bundle, fmt.Errorf("manifest descriptor mismatch for %s", descriptor.Name)
		}
		seenManifestFile[descriptor.Name] = true
	}
	for _, record := range bundle.Licences {
		if record.SchemaVersion != exportdata.SchemaVersion {
			return bundle, fmt.Errorf("unsupported licence record schema")
		}
	}
	for _, record := range bundle.Activations {
		if record.SchemaVersion != exportdata.SchemaVersion {
			return bundle, fmt.Errorf("unsupported activation record schema")
		}
	}
	for _, record := range bundle.Revocations {
		if record.SchemaVersion != exportdata.SchemaVersion {
			return bundle, fmt.Errorf("unsupported revocation record schema")
		}
	}
	for _, record := range bundle.AuditEvents {
		if record.SchemaVersion != exportdata.SchemaVersion {
			return bundle, fmt.Errorf("unsupported audit record schema")
		}
	}
	return bundle, nil
}

func verifyChecksums(files map[string][]byte) error {
	lines := strings.Split(strings.TrimSuffix(string(files["checksums.sha256"]), "\n"), "\n")
	if len(lines) != 5 {
		return fmt.Errorf("checksum catalogue must contain five entries")
	}
	seen := make(map[string]bool)
	for _, line := range lines {
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != sha256.Size*2 || parts[1] == "checksums.sha256" || seen[parts[1]] {
			return fmt.Errorf("invalid checksum catalogue")
		}
		data, exists := files[parts[1]]
		if !exists {
			return fmt.Errorf("checksum references absent file %q", parts[1])
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(parts[0], hex.EncodeToString(sum[:])) {
			return fmt.Errorf("checksum mismatch for %s", parts[1])
		}
		seen[parts[1]] = true
	}
	return nil
}

func decodeSingleJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func decodeNDJSON[T any](data []byte, destination *[]T) error {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var record T
		if err := decodeSingleJSON(scanner.Bytes(), &record); err != nil {
			return err
		}
		*destination = append(*destination, record)
	}
	return scanner.Err()
}
