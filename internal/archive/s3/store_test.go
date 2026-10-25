package s3archive

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/matthogan/licenceserver/internal/domain"
)

type fakeS3 struct {
	objects map[string][]byte
	last    *awss3.PutObjectInput
}

func (f *fakeS3) PutObject(_ context.Context, input *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	f.last = input
	key := aws.ToString(input.Key)
	if _, exists := f.objects[key]; exists {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "exists"}
	}
	body, _ := io.ReadAll(input.Body)
	f.objects[key] = body
	return &awss3.PutObjectOutput{}, nil
}
func (f *fakeS3) GetObject(_ context.Context, input *awss3.GetObjectInput, _ ...func(*awss3.Options)) (*awss3.GetObjectOutput, error) {
	return &awss3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(string(f.objects[aws.ToString(input.Key)])))}, nil
}
func (f *fakeS3) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	objects := make([]types.Object, 0, len(f.objects))
	for key := range f.objects {
		value := key
		objects = append(objects, types.Object{Key: &value})
	}
	return &awss3.ListObjectsV2Output{Contents: objects, IsTruncated: aws.Bool(false)}, nil
}

func TestImmutableEncryptedObjectLockedArchive(t *testing.T) {
	fake := &fakeS3{objects: map[string][]byte{}}
	store, err := NewWithClient(fake, "archive-bucket", "events", "alias/archive", "COMPLIANCE", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	event := domain.ArchiveEvent{SchemaVersion: 1, EventID: "evt_test", EventType: "licence.issued", OccurredAt: time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC), LicenceID: "lic_test", ProductID: "product", PayloadHash: "hash", SignedLicenceArtifact: "artifact", IssuerKeyID: "issuer"}
	if err = store.PutEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if fake.last.IfNoneMatch == nil || *fake.last.IfNoneMatch != "*" || fake.last.ServerSideEncryption != types.ServerSideEncryptionAwsKms || fake.last.ObjectLockMode != types.ObjectLockModeCompliance || fake.last.ChecksumSHA256 == nil {
		t.Fatalf("put controls not enforced: %+v", fake.last)
	}
	if err = store.PutEvent(context.Background(), event); err != nil {
		t.Fatalf("idempotent duplicate: %v", err)
	}
	if err = store.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListEvents(context.Background())
	if err != nil || len(events) != 1 || events[0].EventID != event.EventID {
		t.Fatalf("listed events=%+v err=%v", events, err)
	}
}
