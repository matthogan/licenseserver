package logicalbackup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeS3 struct {
	put  *awss3.PutObjectInput
	page *awss3.ListObjectsV2Output
}

func (f *fakeS3) PutObject(_ context.Context, in *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	f.put = in
	_, _ = io.ReadAll(in.Body)
	return &awss3.PutObjectOutput{}, nil
}
func (f *fakeS3) ListObjectsV2(_ context.Context, _ *awss3.ListObjectsV2Input, _ ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	return f.page, nil
}

func TestCompressAndS3UploadSecurity(t *testing.T) {
	dir := t.TempDir()
	exportDir := filepath.Join(dir, "export")
	if err := os.Mkdir(exportDir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"manifest.json": "{}\n", "products.ndjson": "{\"product_id\":\"p\"}\n"} {
		if err := os.WriteFile(filepath.Join(exportDir, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := Compress(exportDir, archive); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		names = append(names, h.Name)
	}
	_ = gz.Close()
	_ = f.Close()
	if !reflect.DeepEqual(names, []string{"manifest.json", "products.ndjson"}) {
		t.Fatalf("archive entries=%v", names)
	}

	fake := &fakeS3{}
	store := &S3{client: fake, kmsKey: "arn:aws:kms:eu-west-1:123:key/test"}
	uri, err := store.Upload(context.Background(), "s3://backup-bucket/logical/", archive)
	if err != nil {
		t.Fatal(err)
	}
	if uri == "" || aws.ToString(fake.put.IfNoneMatch) != "*" || fake.put.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(fake.put.SSEKMSKeyId) != store.kmsKey || aws.ToString(fake.put.ChecksumSHA256) == "" {
		t.Fatalf("unsafe S3 put: uri=%q input=%+v", uri, fake.put)
	}
}

func TestParseAndListS3(t *testing.T) {
	if _, _, err := ParseS3URI("s3://bucket/good/../escape"); err == nil {
		t.Fatal("accepted parent traversal")
	}
	now := time.Now().UTC()
	fake := &fakeS3{page: &awss3.ListObjectsV2Output{Contents: []types.Object{{Key: aws.String("logical/one.tar.gz"), Size: aws.Int64(42), LastModified: &now}, {Key: aws.String("logical/readme.txt")}}}}
	objects, err := (&S3{client: fake, kmsKey: "key"}).List(context.Background(), "s3://bucket/logical/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || objects[0].URI != "s3://bucket/logical/one.tar.gz" {
		t.Fatalf("objects=%+v", objects)
	}
}
