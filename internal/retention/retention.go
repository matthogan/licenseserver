// Package retention contains database-independent validation and suppression
// identifiers for production retention/deletion workflows.
package retention

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/matthogan/licenceserver/internal/domain"
)

const SchemaVersion = 1

func ValidCategory(category string) bool {
	switch category {
	case domain.RetentionExpiredTrials, domain.RetentionRevokedActivations, domain.RetentionRevokedLicences:
		return true
	default:
		return false
	}
}

func ValidateScope(scope domain.DataScope) error {
	values := []string{scope.ProductID, scope.LicenceID, scope.CustomerRef}
	nonempty := 0
	for _, value := range values {
		if value != "" {
			nonempty++
		}
		if len(value) > 512 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return domain.ErrInvalid
		}
	}
	if nonempty == 0 {
		return domain.ErrInvalid
	}
	return nil
}

func ValidatePolicy(policy domain.RetentionPolicy) error {
	if !ValidCategory(policy.Category) || policy.RetainForSeconds <= 0 || policy.RetainForSeconds > int64(20*365*24*60*60) || strings.TrimSpace(policy.CreatedBy) == "" {
		return domain.ErrInvalid
	}
	return nil
}

func ValidateDeletion(request domain.DataDeletionRequest) error {
	if ValidateScope(request.Scope) != nil || strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		return domain.ErrInvalid
	}
	if request.ExportSHA256 != "" && !validSHA256(request.ExportSHA256) {
		return domain.ErrInvalid
	}
	return nil
}

func ValidExportSHA256(value string) bool {
	return value == "" || validSHA256(value)
}

func Digest(subjectType, identifier string) string {
	sum := sha256.Sum256([]byte("licd-suppression-tombstone-v1\x00" + subjectType + "\x00" + identifier))
	return hex.EncodeToString(sum[:])
}

func ValidateTombstone(tombstone domain.SuppressionTombstone) error {
	if tombstone.SchemaVersion != SchemaVersion || tombstone.SubjectType != "licence" && tombstone.SubjectType != "activation" || !validSHA256(tombstone.SubjectDigest) || tombstone.DeletedAt.IsZero() || strings.TrimSpace(tombstone.ReasonCode) == "" || len(tombstone.ReasonCode) > 64 {
		return domain.ErrInvalid
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
