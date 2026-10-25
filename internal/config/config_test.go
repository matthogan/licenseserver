package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRecoveryDrillValidation(t *testing.T) {
	valid := func() Config {
		c := Defaults()
		c.RecoveryDrill.Enabled = true
		c.RecoveryDrill.ReportDirectory = filepath.Join(t.TempDir(), "reports")
		return c
	}
	t.Run("accept safe scheduled simulation", func(t *testing.T) {
		if err := valid().Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("credentialed requires remote recovery sources", func(t *testing.T) {
		c := valid()
		c.RecoveryDrill.Mode = "credentialed"
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "continuous backup") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("required schedule cannot be disabled", func(t *testing.T) {
		c := Defaults()
		c.RecoveryDrill.Required = true
		if err := c.Validate(false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("reject insecure proxy probe", func(t *testing.T) {
		c := valid()
		c.RecoveryDrill.ReverseProxyURL = "http://proxy.example"
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("report age must cover schedule", func(t *testing.T) {
		c := valid()
		c.RecoveryDrill.MaxReportAge = c.RecoveryDrill.ScheduleInterval - time.Second
		if err := c.Validate(false); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestSecureTransportValidation(t *testing.T) {
	t.Run("secure platform defaults", func(t *testing.T) {
		c := Defaults()
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reject exposed plaintext public API", func(t *testing.T) {
		c := Defaults()
		c.Server.PublicListen = ":9443"
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "insecure public listener") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("accept explicit trusted proxy", func(t *testing.T) {
		c := Defaults()
		c.Server.PublicListen = ":9443"
		c.TLS.ReverseProxy.Enabled = true
		c.TLS.ReverseProxy.TrustedCIDRs = []string{"10.0.0.0/8"}
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reject malformed trusted proxy", func(t *testing.T) {
		c := Defaults()
		c.Server.PublicListen = ":9443"
		c.TLS.ReverseProxy.Enabled = true
		c.TLS.ReverseProxy.TrustedCIDRs = []string{"not-a-cidr"}
		if err := c.Validate(false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("reject insecure TCP admin by default", func(t *testing.T) {
		c := Defaults()
		c.Server.AdminTransport = "tcp"
		c.Server.AdminListen = "127.0.0.1:9444"
		if err := c.Validate(false); err == nil {
			t.Fatal("expected error")
		}
		c.Server.AllowInsecureAdmin = true
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("accept configured admin mTLS", func(t *testing.T) {
		c := Defaults()
		c.Server.AdminTransport = "tcp"
		c.Server.AdminListen = ":9444"
		c.AdminTLS.Enabled = true
		c.AdminTLS.CertificateFile = "server.crt"
		c.AdminTLS.PrivateKeyFile = "server.key"
		c.AdminTLS.ClientCAFile = "client-ca.crt"
		c.AdminAuthorization.Identities = []AdminIdentity{{Match: "operator", Roles: []string{"viewer", "operator"}}}
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reject unknown role", func(t *testing.T) {
		c := Defaults()
		c.AdminAuthorization.Identities = []AdminIdentity{{Match: "person", Roles: []string{"superuser"}}}
		if err := c.Validate(false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("platform local transport", func(t *testing.T) {
		c := Defaults()
		if runtime.GOOS == "windows" && c.Server.AdminTransport != "named_pipe" {
			t.Fatalf("got %s", c.Server.AdminTransport)
		}
		if runtime.GOOS != "windows" && c.Server.AdminTransport != "unix" {
			t.Fatalf("got %s", c.Server.AdminTransport)
		}
	})
	if runtime.GOOS == "windows" {
		t.Run("reject invalid pipe SDDL", func(t *testing.T) {
			c := Defaults()
			c.Server.AdminPipeSDDL = "not-sddl"
			if err := c.Validate(false); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadAuthorizationIdentities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `server:
  public_listen: "127.0.0.1:9443"
  admin_transport: tcp
  admin_listen: ":9444"
admin_tls:
  enabled: true
  certificate_file: server.crt
  private_key_file: server.key
  client_ca_file: client-ca.crt
admin_authorization:
  identities:
    - match: "spiffe://Example.test/Licensing/Operator"
      roles: [viewer, operator]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AdminAuthorization.Identities) != 1 {
		t.Fatalf("identities=%v", c.AdminAuthorization.Identities)
	}
	for _, identity := range c.AdminAuthorization.Identities {
		if len(identity.Roles) != 2 || identity.Roles[1] != "operator" {
			t.Fatalf("identity=%v", identity)
		}
	}
}

func TestAdminClientValidation(t *testing.T) {
	c := Defaults()
	c.Admin.Transport = "tcp"
	c.Admin.URL = "http://198.51.100.1:9444"
	if err := c.ValidateAdminClient(false); err == nil {
		t.Fatal("expected remote plaintext rejection")
	}
	c.Admin.URL = "https://admin.example:9444"
	if err := c.ValidateAdminClient(false); err == nil {
		t.Fatal("expected missing mTLS material")
	}
	c.Admin.TLS.CertificateFile = "client.crt"
	c.Admin.TLS.PrivateKeyFile = "client.key"
	c.Admin.TLS.ServerCAFile = "ca.crt"
	c.Admin.TLS.ServerName = "admin.example"
	if err := c.ValidateAdminClient(false); err != nil {
		t.Fatal(err)
	}
}

func TestContinuousBackupValidation(t *testing.T) {
	valid := func() Config {
		c := Defaults()
		c.Backup.Continuous.Enabled = true
		c.Backup.Continuous.ReplicaURL = "s3://licd-backups/production/licensing.db"
		c.Backup.Continuous.S3.Encryption.Mode = "sse-kms"
		c.Backup.Continuous.S3.Encryption.KMSKeyID = "arn:aws:kms:eu-west-1:123456789012:key/example"
		return c
	}
	t.Run("accept encrypted S3", func(t *testing.T) {
		if err := valid().Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("reject missing encryption", func(t *testing.T) {
		c := valid()
		c.Backup.Continuous.S3.Encryption.Mode = ""
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "unencrypted") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("reject URL credentials", func(t *testing.T) {
		c := valid()
		c.Backup.Continuous.ReplicaURL = "s3://access:secret@bucket/path"
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "credentials") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("reject plaintext endpoint", func(t *testing.T) {
		c := valid()
		c.Backup.Continuous.S3.Endpoint = "http://minio.example:9000"
		if err := c.Validate(false); err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("require SSE-C environment", func(t *testing.T) {
		c := valid()
		c.Backup.Continuous.S3.Encryption.Mode = "sse-c"
		c.Backup.Continuous.S3.Encryption.KMSKeyID = ""
		c.Backup.Continuous.S3.Encryption.CustomerKeyEnv = "LICD_TEST_SSE_C_KEY"
		if err := c.validateContinuousBackup(true); err == nil || !strings.Contains(err.Error(), "LICD_TEST_SSE_C_KEY") {
			t.Fatalf("got %v", err)
		}
		t.Setenv("LICD_TEST_SSE_C_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
		if err := c.validateContinuousBackup(true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestContinuousBackupEnvironmentOverrides(t *testing.T) {
	t.Setenv("LICD_BACKUP_CONTINUOUS_ENABLED", "true")
	t.Setenv("LICD_BACKUP_CONTINUOUS_REPLICA_URL", "s3://environment-bucket/licd.db")
	t.Setenv("LICD_BACKUP_CONTINUOUS_S3_REGION", "eu-central-1")
	t.Setenv("LICD_BACKUP_CONTINUOUS_S3_ENCRYPTION_KMS_KEY_ID", "alias/from-environment")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Backup.Continuous.Enabled || c.Backup.Continuous.ReplicaURL != "s3://environment-bucket/licd.db" || c.Backup.Continuous.S3.Region != "eu-central-1" {
		t.Fatalf("backup config=%+v", c.Backup.Continuous)
	}
}

func TestActivationPepperValidation(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(root, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := Defaults()
	c.Signer.RootPublicKeyFile = root
	c.Signer.KeyDirectory = dir
	t.Setenv(c.Trial.PepperEnv, "a-distinct-trial-pepper-that-is-long")
	t.Setenv(c.Activation.PepperEnv, "a-production-activation-pepper-long-enough")
	t.Setenv(c.RateLimit.PepperEnv, "a-third-rate-limit-pepper-long-enough")
	if err := c.Validate(true); err != nil {
		t.Fatal(err)
	}
	t.Setenv(c.Activation.PepperEnv, "short")
	if err := c.Validate(true); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("got %v", err)
	}
	same := "same-pepper-value-that-is-long-enough"
	t.Setenv(c.Trial.PepperEnv, same)
	t.Setenv(c.Activation.PepperEnv, same)
	if err := c.Validate(true); err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("got %v", err)
	}
}

func TestProductionAdapterValidation(t *testing.T) {
	t.Run("postgres", func(t *testing.T) {
		c := Defaults()
		c.Database.Driver = "postgres"
		c.Backup.Continuous.Enabled = false
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
		c.Database.Postgres.MinConnections = c.Database.Postgres.MaxConnections + 1
		if err := c.Validate(false); err == nil {
			t.Fatal("invalid PostgreSQL pool accepted")
		}
	})
	t.Run("S3 archive", func(t *testing.T) {
		c := Defaults()
		c.Archive.Provider = "s3"
		c.Archive.S3.Bucket = "archive"
		c.Archive.S3.Region = "eu-west-1"
		c.Archive.S3.KMSKeyID = "alias/archive"
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
		c.Archive.S3.Endpoint = "http://insecure.example"
		if err := c.Validate(false); err == nil {
			t.Fatal("insecure S3 endpoint accepted")
		}
	})
	t.Run("KMS signer", func(t *testing.T) {
		c := Defaults()
		c.Signer.Provider = "aws-kms"
		c.Signer.KMS.KeyID = "arn:key"
		c.Signer.KMS.Region = "eu-west-1"
		c.Signer.IssuerCertificateFile = "issuer.cert"
		if err := c.Validate(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rotating file", func(t *testing.T) {
		c := Defaults()
		c.Logging.Output = "relative.log"
		if err := c.Validate(false); err == nil {
			t.Fatal("relative log path accepted")
		}
	})
}

func TestProductionAdapterExampleLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "configs", "config.postgres-kms-s3.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Database.Driver != "postgres" || c.Signer.Provider != "aws-kms" || c.Archive.Provider != "s3" {
		t.Fatalf("adapters not loaded: database=%s signer=%s archive=%s", c.Database.Driver, c.Signer.Provider, c.Archive.Provider)
	}
}
