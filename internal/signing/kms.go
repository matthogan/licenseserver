package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/matthogan/licenceserver/internal/licencefmt"
)

type kmsClient interface {
	GetPublicKey(context.Context, *awskms.GetPublicKeyInput, ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
	Sign(context.Context, *awskms.SignInput, ...func(*awskms.Options)) (*awskms.SignOutput, error)
}

type KMS struct {
	client             kmsClient
	keyRef             string
	keyID              string
	public             ed25519.PublicKey
	certificate        string
	certificatePayload licencefmt.IssuerCertificatePayload
}

func LoadKMS(ctx context.Context, keyRef, region, endpoint, certificate string) (*KMS, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS KMS configuration: %w", err)
	}
	client := awskms.NewFromConfig(awsCfg, func(o *awskms.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return LoadKMSWithClient(ctx, client, keyRef, certificate)
}

func LoadKMSWithClient(ctx context.Context, client kmsClient, keyRef, certificate string) (*KMS, error) {
	if client == nil || strings.TrimSpace(keyRef) == "" {
		return nil, errors.New("KMS client and key reference are required")
	}
	cert, payload, err := parseCertificatePayload(certificate)
	if err != nil {
		return nil, err
	}
	result, err := client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: aws.String(keyRef)})
	if err != nil {
		return nil, fmt.Errorf("get KMS issuer public key: %w", err)
	}
	if result.KeySpec != types.KeySpecEccNistEdwards25519 || result.KeyUsage != types.KeyUsageTypeSignVerify || !containsAlgorithm(result.SigningAlgorithms, types.SigningAlgorithmSpecEd25519Sha512) {
		return nil, errors.New("KMS key must be ECC_NIST_EDWARDS25519 with SIGN_VERIFY and ED25519_SHA_512")
	}
	parsed, err := x509.ParsePKIXPublicKey(result.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KMS public key: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("KMS public key is not Ed25519")
	}
	certPublic, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil || !public.Equal(ed25519.PublicKey(certPublic)) {
		return nil, errors.New("KMS public key does not match issuer certificate")
	}
	return &KMS{client: client, keyRef: keyRef, keyID: payload.IssuerKeyID, public: append(ed25519.PublicKey(nil), public...), certificate: cert, certificatePayload: payload}, nil
}

func (k *KMS) KeyID() string                                           { return k.keyID }
func (k *KMS) Algorithm() string                                       { return "Ed25519" }
func (k *KMS) Certificate() string                                     { return k.certificate }
func (k *KMS) CertificatePayload() licencefmt.IssuerCertificatePayload { return k.certificatePayload }
func (k *KMS) PublicKey() []byte                                       { return append([]byte(nil), k.public...) }
func (k *KMS) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if len(message) > 4096 {
		return nil, errors.New("KMS signing message exceeds 4096-byte RAW limit")
	}
	result, err := k.client.Sign(ctx, &awskms.SignInput{KeyId: aws.String(k.keyRef), Message: message, MessageType: types.MessageTypeRaw, SigningAlgorithm: types.SigningAlgorithmSpecEd25519Sha512})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if len(result.Signature) != ed25519.SignatureSize || !ed25519.Verify(k.public, message, result.Signature) {
		return nil, errors.New("KMS returned an invalid Ed25519 signature")
	}
	return append([]byte(nil), result.Signature...), nil
}

func parseCertificatePayload(certificate string) (string, licencefmt.IssuerCertificatePayload, error) {
	var payload licencefmt.IssuerCertificatePayload
	cert := strings.TrimSpace(certificate)
	parts := strings.Split(cert, ".")
	if len(parts) != 3 || parts[0] != "ISC1" {
		return "", payload, errors.New("malformed issuer certificate")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &payload) != nil || payload.Algorithm != "Ed25519" || payload.IssuerKeyID == "" {
		return "", payload, errors.New("malformed issuer certificate payload")
	}
	return cert, payload, nil
}

func containsAlgorithm(values []types.SigningAlgorithmSpec, wanted types.SigningAlgorithmSpec) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
