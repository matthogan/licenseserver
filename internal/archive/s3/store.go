package s3archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/retention"
)

const (
	maxArchiveEventBytes = 1024 * 1024
	maxArchiveEvents     = 1000000
)

type client interface {
	PutObject(context.Context, *awss3.PutObjectInput, ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	GetObject(context.Context, *awss3.GetObjectInput, ...func(*awss3.Options)) (*awss3.GetObjectOutput, error)
	ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
}

type Store struct {
	client   client
	bucket   string
	prefix   string
	kmsKeyID string
	lockMode types.ObjectLockMode
	lockFor  time.Duration
}

func New(ctx context.Context, c config.Config) (*Store, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.Archive.S3.Region))
	if err != nil {
		return nil, fmt.Errorf("load AWS archive configuration: %w", err)
	}
	client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.UsePathStyle = c.Archive.S3.ForcePathStyle
		if c.Archive.S3.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Archive.S3.Endpoint)
		}
	})
	return NewWithClient(client, c.Archive.S3.Bucket, c.Archive.S3.Prefix, c.Archive.S3.KMSKeyID, c.Archive.S3.ObjectLockMode, c.Archive.S3.ObjectLockFor)
}

// NewReader opens an archive source identified by an s3:// URL using the
// configured region, endpoint and standard AWS credential chain. It does not
// grant write behavior unless the returned store also has valid write policy.
func NewReader(ctx context.Context, c config.Config, source string) (*Store, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("archive source must be an absolute s3:// URL")
	}
	if c.Archive.S3.Region == "" {
		return nil, errors.New("archive.s3.region is required for S3 archive reads")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.Archive.S3.Region))
	if err != nil {
		return nil, fmt.Errorf("load AWS archive configuration: %w", err)
	}
	client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.UsePathStyle = c.Archive.S3.ForcePathStyle
		if c.Archive.S3.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Archive.S3.Endpoint)
		}
	})
	return &Store{client: client, bucket: u.Host, prefix: strings.Trim(u.Path, "/")}, nil
}

func NewWithClient(api client, bucket, prefix, kmsKeyID, lockMode string, lockFor time.Duration) (*Store, error) {
	if api == nil || bucket == "" || kmsKeyID == "" || lockFor <= 0 {
		return nil, errors.New("S3 archive client, bucket, KMS key, and retention are required")
	}
	mode := types.ObjectLockMode(lockMode)
	if mode != types.ObjectLockModeGovernance && mode != types.ObjectLockModeCompliance {
		return nil, errors.New("invalid S3 archive Object Lock mode")
	}
	return &Store{client: api, bucket: bucket, prefix: strings.Trim(strings.TrimSpace(prefix), "/"), kmsKeyID: kmsKeyID, lockMode: mode, lockFor: lockFor}, nil
}

func (s *Store) PutEvent(ctx context.Context, event domain.ArchiveEvent) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	body, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	key := s.eventKey(event)
	sum := sha256.Sum256(body)
	for attempt := 0; attempt < 3; attempt++ {
		retainUntil := time.Now().UTC().Add(s.lockFor)
		_, err = s.client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(body),
			ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*"),
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])),
			ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(s.kmsKeyID),
			ObjectLockMode: s.lockMode, ObjectLockRetainUntilDate: &retainUntil,
		})
		if err == nil {
			return nil
		}
		if apiCode(err) == "ConditionalRequestConflict" {
			continue
		}
		if apiCode(err) != "PreconditionFailed" {
			return fmt.Errorf("put immutable archive event: %w", err)
		}
		existing, getErr := s.get(ctx, key)
		if getErr != nil {
			return getErr
		}
		if bytes.Equal(existing, body) {
			return nil
		}
		return fmt.Errorf("archive event %s already exists with different content", event.EventID)
	}
	return errors.New("S3 archive conditional write remained conflicted after retries")
}

func (s *Store) Verify(ctx context.Context) error {
	_, err := s.ListEvents(ctx)
	return err
}

func (s *Store) ListEvents(ctx context.Context) ([]domain.ArchiveEvent, error) {
	prefix := s.prefix
	if prefix != "" {
		prefix += "/"
	}
	var token *string
	var events []domain.ArchiveEvent
	for {
		page, err := s.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(prefix), ContinuationToken: token})
		if err != nil {
			return nil, fmt.Errorf("list archive events: %w", err)
		}
		for _, object := range page.Contents {
			key := aws.ToString(object.Key)
			if !strings.HasSuffix(key, ".json") {
				continue
			}
			body, getErr := s.get(ctx, key)
			if getErr != nil {
				return nil, getErr
			}
			var event domain.ArchiveEvent
			if json.Unmarshal(body, &event) != nil || validateEvent(event) != nil || path.Base(key) != event.EventID+".json" {
				return nil, fmt.Errorf("invalid archive event object %s", key)
			}
			events = append(events, event)
			if len(events) > maxArchiveEvents {
				return nil, errors.New("archive event count exceeds safety limit")
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			sort.Slice(events, func(i, j int) bool {
				if events[i].OccurredAt.Equal(events[j].OccurredAt) {
					return events[i].EventID < events[j].EventID
				}
				return events[i].OccurredAt.Before(events[j].OccurredAt)
			})
			return events, nil
		}
		token = page.NextContinuationToken
		if token == nil {
			return nil, errors.New("S3 returned a truncated archive listing without a continuation token")
		}
	}
}

func (s *Store) get(ctx context.Context, key string) ([]byte, error) {
	result, err := s.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("read archive event %s: %w", key, err)
	}
	defer result.Body.Close()
	body, err := io.ReadAll(io.LimitReader(result.Body, maxArchiveEventBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxArchiveEventBytes {
		return nil, fmt.Errorf("archive event %s exceeds size limit", key)
	}
	return body, nil
}

func (s *Store) eventKey(event domain.ArchiveEvent) string {
	return path.Join(s.prefix, event.OccurredAt.UTC().Format("2006/01/02"), event.EventID+".json")
}

func validateEvent(event domain.ArchiveEvent) error {
	if event.SchemaVersion != 1 || event.EventID == "" || strings.ContainsAny(event.EventID, `/\\`) {
		return errors.New("invalid archive event")
	}
	switch event.EventType {
	case "licence.issued":
		if event.LicenceID == "" || event.ProductID == "" || event.PayloadHash == "" || event.SignedLicenceArtifact == "" || event.IssuerKeyID == "" {
			return errors.New("invalid licence-issued archive event")
		}
	case "licence.revoked":
		if event.LicenceID == "" || event.Revocation == nil || event.Revocation.LicenceID != event.LicenceID {
			return errors.New("invalid licence-revoked archive event")
		}
	case "data.suppressed":
		if event.LicenceID != "" || event.ProductID != "" || event.CustomerRef != "" || event.PurchaseRef != "" || event.PayloadHash != "" || event.SignedLicenceArtifact != "" || event.IssuerKeyID != "" || event.Revocation != nil || event.Suppression == nil || retention.ValidateTombstone(*event.Suppression) != nil || !event.OccurredAt.Equal(event.Suppression.DeletedAt) {
			return errors.New("invalid data-suppressed archive event")
		}
	default:
		return errors.New("unsupported archive event type")
	}
	return nil
}

func apiCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}
