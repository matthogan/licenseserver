package logicalbackup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
)

type RemoteObject struct {
	URI          string    `json:"uri"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

type s3API interface {
	PutObject(context.Context, *awss3.PutObjectInput, ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
}

type S3 struct {
	client s3API
	kmsKey string
}

func NewS3(ctx context.Context, cfg config.Config) (*S3, error) {
	b := cfg.Backup.Continuous.S3
	if b.Region == "" {
		return nil, errors.New("backup.continuous.s3.region is required for logical S3 exports")
	}
	if b.Encryption.Mode != "sse-kms" {
		return nil, errors.New("logical S3 exports require backup.continuous.s3.encryption.mode=sse-kms")
	}
	kmsKey := strings.TrimSpace(b.Encryption.KMSKeyID)
	if kmsKey == "" && b.Encryption.KMSKeyIDEnv != "" {
		kmsKey = strings.TrimSpace(os.Getenv(b.Encryption.KMSKeyIDEnv))
	}
	if kmsKey == "" {
		return nil, errors.New("logical S3 exports require a KMS key ID or configured KMS key environment variable")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(b.Region))
	if err != nil {
		return nil, fmt.Errorf("load AWS logical-backup configuration: %w", err)
	}
	client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.UsePathStyle = b.ForcePathStyle
		if b.Endpoint != "" {
			o.BaseEndpoint = aws.String(b.Endpoint)
		}
	})
	return &S3{client: client, kmsKey: kmsKey}, nil
}

func ParseS3URI(raw string) (bucket, key string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("destination must be an s3://bucket/prefix URI")
	}
	key = strings.TrimPrefix(u.EscapedPath(), "/")
	key, err = url.PathUnescape(key)
	if err != nil || strings.Contains(key, "\\") || strings.Contains("/"+key+"/", "/../") {
		return "", "", errors.New("invalid S3 object prefix")
	}
	return u.Host, strings.TrimPrefix(key, "/"), nil
}

func (s *S3) Upload(ctx context.Context, destination, localFile string) (string, error) {
	bucket, key, err := ParseS3URI(destination)
	if err != nil {
		return "", err
	}
	if key == "" || strings.HasSuffix(key, "/") {
		key = path.Join(key, "licensing-logical-"+time.Now().UTC().Format("20060102T150405Z")+"-"+uuid.NewString()+".tar.gz")
	}
	f, err := os.Open(localFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	_, err = s.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: f,
		ContentType: aws.String("application/gzip"), IfNoneMatch: aws.String("*"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(h.Sum(nil))),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(s.kmsKey),
	})
	if err != nil {
		return "", fmt.Errorf("upload immutable logical backup: %w", err)
	}
	return "s3://" + bucket + "/" + key, nil
}

func (s *S3) List(ctx context.Context, destination string) ([]RemoteObject, error) {
	bucket, prefix, err := ParseS3URI(destination)
	if err != nil {
		return nil, err
	}
	var out []RemoteObject
	var token *string
	for {
		page, listErr := s.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix), ContinuationToken: token})
		if listErr != nil {
			return nil, fmt.Errorf("list logical backups: %w", listErr)
		}
		for _, object := range page.Contents {
			key := aws.ToString(object.Key)
			if strings.HasSuffix(key, ".tar.gz") {
				out = append(out, RemoteObject{URI: "s3://" + bucket + "/" + key, Size: aws.ToInt64(object.Size), LastModified: aws.ToTime(object.LastModified)})
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		token = page.NextContinuationToken
		if token == nil {
			return nil, errors.New("S3 returned a truncated listing without a continuation token")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastModified.After(out[j].LastModified) })
	return out, nil
}

// Compress creates an exclusive gzip-compressed POSIX tar containing only
// regular export files. Entry names are relative and stable across platforms.
func Compress(directory, output string) error {
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("refusing to overwrite %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if err = os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(output)
		}
	}()
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.Name = filepath.Base(output)
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("logical export contains non-regular entry %s", entry.Name())
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		header := &tar.Header{Name: entry.Name(), Mode: 0o640, Size: info.Size(), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err = tw.WriteHeader(header); err != nil {
			return err
		}
		in, openErr := os.Open(filepath.Join(directory, entry.Name()))
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(tw, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if err = gz.Close(); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
