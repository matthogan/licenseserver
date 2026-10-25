package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
)

type fakeKMS struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (f fakeKMS) GetPublicKey(context.Context, *awskms.GetPublicKeyInput, ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	der, _ := x509.MarshalPKIXPublicKey(f.public)
	return &awskms.GetPublicKeyOutput{KeyId: aws.String("arn:key"), KeySpec: types.KeySpecEccNistEdwards25519, KeyUsage: types.KeyUsageTypeSignVerify, PublicKey: der, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEd25519Sha512}}, nil
}
func (f fakeKMS) Sign(_ context.Context, input *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	return &awskms.SignOutput{Signature: ed25519.Sign(f.private, input.Message), SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512}, nil
}

func TestKMSSignerProducesCompatibleLicence(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	cert, err := licencefmt.CreateIssuerCertificate(rootPrivate, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "kms-issuer", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(public), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"product"}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := LoadKMSWithClient(context.Background(), fakeKMS{public, private}, "arn:key", cert)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(signer)
	signed, err := manager.Sign(context.Background(), domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic", ProductID: "product", LicenceType: "perpetual", IssuedAt: now, NotBefore: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	artifact, _ := licencefmt.MarshalArtifact(signed.Envelope, signed.Certificate)
	if _, err = licencefmt.VerifyArtifact(rootPublic, artifact, "product", now); err != nil {
		t.Fatal(err)
	}
	status, err := manager.SignStatus(context.Background(), domain.LicenceStatusPayload{SchemaVersion: 1, LicenceID: "lic", ProductID: "product", Status: "active", CheckedAt: now, ValidUntil: now.Add(5 * time.Minute), Nonce: "0123456789abcdef"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = licencefmt.VerifyStatus(rootPublic, status, "lic", "product", "0123456789abcdef", now, time.Minute); err != nil {
		t.Fatal(err)
	}
}
