package retention

import (
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

func TestSuppressionDigestIsDomainSeparatedAndStable(t *testing.T) {
	const want = "58206ca68685ca7a537906162e03a7e66d3b948511ed26970a1cc5ccefd44237"
	if got := Digest("licence", "lic-example"); got != want {
		t.Fatalf("digest changed: %s", got)
	}
	if Digest("activation", "lic-example") == want {
		t.Fatal("subject types were not domain separated")
	}
	valid := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "licence", SubjectDigest: want, DeletedAt: time.Now().UTC(), ReasonCode: "manual_deletion"}
	if err := ValidateTombstone(valid); err != nil {
		t.Fatal(err)
	}
	valid.SubjectDigest = "not-a-digest"
	if ValidateTombstone(valid) == nil {
		t.Fatal("invalid digest accepted")
	}
}
