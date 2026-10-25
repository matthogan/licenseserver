package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/admintransport"
	"github.com/matthogan/licenceserver/internal/secretvalue"
	"github.com/spf13/viper"
)

type AdminIdentity struct {
	Match string   `mapstructure:"match"`
	Roles []string `mapstructure:"roles"`
}

type Config struct {
	Server struct {
		PublicListen       string `mapstructure:"public_listen"`
		AdminTransport     string `mapstructure:"admin_transport"`
		AdminListen        string `mapstructure:"admin_listen"`
		AdminSocket        string `mapstructure:"admin_socket"`
		AdminSocketMode    string `mapstructure:"admin_socket_mode"`
		AdminPipe          string `mapstructure:"admin_pipe"`
		AdminPipeSDDL      string `mapstructure:"admin_pipe_sddl"`
		AllowInsecureAdmin bool   `mapstructure:"allow_insecure_admin"`
		ReadOnly           bool   `mapstructure:"read_only"`
	} `mapstructure:"server"`
	TLS struct {
		Enabled         bool   `mapstructure:"enabled"`
		MinVersion      string `mapstructure:"min_version"`
		CertificateFile string `mapstructure:"certificate_file"`
		PrivateKeyFile  string `mapstructure:"private_key_file"`
		ReverseProxy    struct {
			Enabled      bool     `mapstructure:"enabled"`
			TrustedCIDRs []string `mapstructure:"trusted_cidrs"`
		} `mapstructure:"reverse_proxy"`
	} `mapstructure:"tls"`
	AdminTLS struct {
		Enabled         bool   `mapstructure:"enabled"`
		CertificateFile string `mapstructure:"certificate_file"`
		PrivateKeyFile  string `mapstructure:"private_key_file"`
		ClientCAFile    string `mapstructure:"client_ca_file"`
	} `mapstructure:"admin_tls"`
	AdminAuthorization struct {
		Identities []AdminIdentity `mapstructure:"identities"`
	} `mapstructure:"admin_authorization"`
	Database struct {
		Driver                string        `mapstructure:"driver"`
		DSN                   string        `mapstructure:"dsn"`
		DSNEnv                string        `mapstructure:"dsn_env"`
		MigrationBackupMaxAge time.Duration `mapstructure:"migration_backup_max_age"`
		SQLite                struct {
			JournalMode string        `mapstructure:"journal_mode"`
			Synchronous string        `mapstructure:"synchronous"`
			ForeignKeys bool          `mapstructure:"foreign_keys"`
			BusyTimeout time.Duration `mapstructure:"busy_timeout"`
		} `mapstructure:"sqlite"`
		Postgres struct {
			MaxConnections  int32         `mapstructure:"max_connections"`
			MinConnections  int32         `mapstructure:"min_connections"`
			MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
		} `mapstructure:"postgres"`
	} `mapstructure:"database"`
	Signer struct {
		Provider              string `mapstructure:"provider"`
		RootPublicKeyFile     string `mapstructure:"root_public_key_file"`
		KeyDirectory          string `mapstructure:"key_directory"`
		PrivateKeyFile        string `mapstructure:"private_key_file"`
		IssuerCertificateFile string `mapstructure:"issuer_certificate_file"`
		KMS                   struct {
			KeyID    string `mapstructure:"key_id"`
			Region   string `mapstructure:"region"`
			Endpoint string `mapstructure:"endpoint"`
		} `mapstructure:"kms"`
	} `mapstructure:"signer"`
	Archive struct {
		Provider             string `mapstructure:"provider"`
		Directory            string `mapstructure:"directory"`
		PaidLicenceAckPolicy string `mapstructure:"paid_licence_ack_policy"`
		S3                   struct {
			Bucket         string        `mapstructure:"bucket"`
			Prefix         string        `mapstructure:"prefix"`
			Region         string        `mapstructure:"region"`
			Endpoint       string        `mapstructure:"endpoint"`
			ForcePathStyle bool          `mapstructure:"force_path_style"`
			Encryption     string        `mapstructure:"encryption"`
			KMSKeyID       string        `mapstructure:"kms_key_id"`
			ObjectLockMode string        `mapstructure:"object_lock_mode"`
			ObjectLockFor  time.Duration `mapstructure:"object_lock_for"`
		} `mapstructure:"s3"`
	} `mapstructure:"archive"`
	Backup struct {
		Continuous struct {
			Enabled             bool          `mapstructure:"enabled"`
			Required            bool          `mapstructure:"required"`
			Binary              string        `mapstructure:"binary"`
			ConfigFile          string        `mapstructure:"config_file"`
			ReplicaURL          string        `mapstructure:"replica_url"`
			SyncInterval        time.Duration `mapstructure:"sync_interval"`
			SnapshotInterval    time.Duration `mapstructure:"snapshot_interval"`
			Retention           time.Duration `mapstructure:"retention"`
			ValidationInterval  time.Duration `mapstructure:"validation_interval"`
			HealthCheckInterval time.Duration `mapstructure:"health_check_interval"`
			MaxBackupAge        time.Duration `mapstructure:"max_backup_age"`
			ShutdownTimeout     time.Duration `mapstructure:"shutdown_timeout"`
			S3                  struct {
				Region         string `mapstructure:"region"`
				Endpoint       string `mapstructure:"endpoint"`
				ForcePathStyle bool   `mapstructure:"force_path_style"`
				Encryption     struct {
					Mode           string `mapstructure:"mode"`
					KMSKeyID       string `mapstructure:"kms_key_id"`
					KMSKeyIDEnv    string `mapstructure:"kms_key_id_env"`
					CustomerKeyEnv string `mapstructure:"customer_key_env"`
				} `mapstructure:"encryption"`
			} `mapstructure:"s3"`
		} `mapstructure:"continuous"`
	} `mapstructure:"backup"`
	RecoveryDrill struct {
		Enabled                  bool          `mapstructure:"enabled"`
		Required                 bool          `mapstructure:"required"`
		Mode                     string        `mapstructure:"mode"`
		ScheduleInterval         time.Duration `mapstructure:"schedule_interval"`
		MaxReportAge             time.Duration `mapstructure:"max_report_age"`
		Timeout                  time.Duration `mapstructure:"timeout"`
		RPOObjective             time.Duration `mapstructure:"rpo_objective"`
		RTOObjective             time.Duration `mapstructure:"rto_objective"`
		ReportDirectory          string        `mapstructure:"report_directory"`
		ReportRetention          time.Duration `mapstructure:"report_retention"`
		ReverseProxyURL          string        `mapstructure:"reverse_proxy_url"`
		RequireReverseProxy      bool          `mapstructure:"require_reverse_proxy"`
		MaxMemoryBytes           uint64        `mapstructure:"max_memory_bytes"`
		MaxGoroutines            int           `mapstructure:"max_goroutines"`
		MaxTemporaryStorageBytes int64         `mapstructure:"max_temporary_storage_bytes"`
	} `mapstructure:"recovery_drill"`
	Trial struct {
		DefaultDuration time.Duration `mapstructure:"default_duration"`
		PepperEnv       string        `mapstructure:"pepper_env"`
	} `mapstructure:"trial"`
	Activation struct {
		PepperEnv string `mapstructure:"pepper_env"`
	} `mapstructure:"activation"`
	RateLimit struct {
		PepperEnv string        `mapstructure:"pepper_env"`
		Window    time.Duration `mapstructure:"window"`
		Retention time.Duration `mapstructure:"retention"`
		Trial     struct {
			PerIP      int `mapstructure:"per_ip"`
			PerSubject int `mapstructure:"per_subject"`
			PerProduct int `mapstructure:"per_product"`
		} `mapstructure:"trial"`
		Activation struct {
			PerIP   int `mapstructure:"per_ip"`
			PerCode int `mapstructure:"per_code"`
		} `mapstructure:"activation"`
		Status struct {
			PerIP int `mapstructure:"per_ip"`
		} `mapstructure:"status"`
	} `mapstructure:"rate_limit"`
	HTTP struct {
		MaxBodyBytes      int64         `mapstructure:"max_body_bytes"`
		MaxHeaderBytes    int           `mapstructure:"max_header_bytes"`
		ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
		ReadTimeout       time.Duration `mapstructure:"read_timeout"`
		WriteTimeout      time.Duration `mapstructure:"write_timeout"`
		IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	} `mapstructure:"http"`
	Logging struct {
		Format string `mapstructure:"format"`
		Level  string `mapstructure:"level"`
		Output string `mapstructure:"output"`
		File   struct {
			MaxSizeBytes int64         `mapstructure:"max_size_bytes"`
			MaxBackups   int           `mapstructure:"max_backups"`
			MaxAge       time.Duration `mapstructure:"max_age"`
		} `mapstructure:"file"`
	} `mapstructure:"logging"`
	Admin struct {
		Transport string `mapstructure:"transport"`
		URL       string `mapstructure:"url"`
		Socket    string `mapstructure:"socket"`
		Pipe      string `mapstructure:"pipe"`
		TLS       struct {
			CertificateFile string `mapstructure:"certificate_file"`
			PrivateKeyFile  string `mapstructure:"private_key_file"`
			ServerCAFile    string `mapstructure:"server_ca_file"`
			ServerName      string `mapstructure:"server_name"`
		} `mapstructure:"tls"`
	} `mapstructure:"admin"`
}

func Defaults() Config {
	var c Config
	c.Server.PublicListen = "127.0.0.1:9443"
	c.Server.AdminTransport = defaultAdminTransport()
	c.Server.AdminListen = "127.0.0.1:9444"
	c.Server.AdminSocket = defaultAdminSocket()
	c.Server.AdminSocketMode = "0660"
	c.Server.AdminPipe = `\\.\pipe\licd`
	c.Server.AdminPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	c.Database.Driver = "sqlite"
	c.Database.DSN = defaultDataPath()
	c.Database.DSNEnv = "LICD_DATABASE_URL"
	c.Database.MigrationBackupMaxAge = 24 * time.Hour
	c.Database.SQLite.JournalMode = "WAL"
	c.Database.SQLite.Synchronous = "FULL"
	c.Database.SQLite.ForeignKeys = true
	c.Database.SQLite.BusyTimeout = 5 * time.Second
	c.Database.Postgres.MaxConnections = 20
	c.Database.Postgres.MinConnections = 2
	c.Database.Postgres.MaxConnLifetime = time.Hour
	c.Signer.Provider = "file"
	c.Archive.Provider = "filesystem"
	c.Archive.Directory = filepath.Join(filepath.Dir(c.Database.DSN), "archive")
	c.Archive.PaidLicenceAckPolicy = "strict"
	c.Archive.S3.Prefix = "licence-events"
	c.Archive.S3.Encryption = "sse-kms"
	c.Archive.S3.ObjectLockMode = "COMPLIANCE"
	c.Archive.S3.ObjectLockFor = 365 * 24 * time.Hour
	c.Backup.Continuous.Required = true
	c.Backup.Continuous.Binary = "litestream"
	c.Backup.Continuous.ConfigFile = ""
	c.Backup.Continuous.SyncInterval = time.Second
	c.Backup.Continuous.SnapshotInterval = 24 * time.Hour
	c.Backup.Continuous.Retention = 30 * 24 * time.Hour
	c.Backup.Continuous.ValidationInterval = 5 * time.Minute
	c.Backup.Continuous.HealthCheckInterval = time.Minute
	c.Backup.Continuous.MaxBackupAge = 5 * time.Minute
	c.Backup.Continuous.ShutdownTimeout = 30 * time.Second
	c.Backup.Continuous.S3.Encryption.Mode = "sse-kms"
	c.RecoveryDrill.Mode = "simulation"
	c.RecoveryDrill.ScheduleInterval = 7 * 24 * time.Hour
	c.RecoveryDrill.MaxReportAge = 8 * 24 * time.Hour
	c.RecoveryDrill.Timeout = 2 * time.Hour
	c.RecoveryDrill.RPOObjective = 5 * time.Minute
	c.RecoveryDrill.RTOObjective = time.Hour
	c.RecoveryDrill.ReportDirectory = filepath.Join(filepath.Dir(c.Database.DSN), "recovery-drills")
	c.RecoveryDrill.ReportRetention = 180 * 24 * time.Hour
	c.RecoveryDrill.MaxMemoryBytes = 512 * 1024 * 1024
	c.RecoveryDrill.MaxGoroutines = 1000
	c.RecoveryDrill.MaxTemporaryStorageBytes = 20 * 1024 * 1024 * 1024
	c.Trial.DefaultDuration = 30 * 24 * time.Hour
	c.Trial.PepperEnv = "LICD_TRIAL_PEPPER"
	c.Activation.PepperEnv = "LICD_ACTIVATION_PEPPER"
	c.RateLimit.PepperEnv = "LICD_RATE_LIMIT_PEPPER"
	c.RateLimit.Window = time.Minute
	c.RateLimit.Retention = 24 * time.Hour
	c.RateLimit.Trial.PerIP = 10
	c.RateLimit.Trial.PerSubject = 3
	c.RateLimit.Trial.PerProduct = 100
	c.RateLimit.Activation.PerIP = 20
	c.RateLimit.Activation.PerCode = 20
	c.RateLimit.Status.PerIP = 60
	c.HTTP.MaxBodyBytes = 65536
	c.HTTP.MaxHeaderBytes = 16384
	c.HTTP.ReadHeaderTimeout = 5 * time.Second
	c.HTTP.ReadTimeout = 10 * time.Second
	c.HTTP.WriteTimeout = 15 * time.Second
	c.HTTP.IdleTimeout = 60 * time.Second
	c.Logging.Format = "json"
	c.Logging.Level = "info"
	c.Logging.Output = "stdout"
	c.Logging.File.MaxSizeBytes = 10 * 1024 * 1024
	c.Logging.File.MaxBackups = 10
	c.Logging.File.MaxAge = 30 * 24 * time.Hour
	c.TLS.MinVersion = "1.3"
	c.Admin.Transport = c.Server.AdminTransport
	c.Admin.URL = "http://127.0.0.1:9444"
	c.Admin.Socket = c.Server.AdminSocket
	c.Admin.Pipe = c.Server.AdminPipe
	return c
}

func NewViper() *viper.Viper {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("LICD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	return v
}

func Load(path string) (Config, error) {
	c, err := loadRaw(path)
	if err != nil {
		return c, err
	}
	return c, c.Validate(false)
}

func LoadClient(path string) (Config, error) {
	c, err := loadRaw(path)
	if err != nil {
		return c, err
	}
	return c, c.ValidateAdminClient(true)
}

func loadRaw(path string) (Config, error) {
	c := Defaults()
	v := NewViper()
	setDefaults(v, c)
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return c, err
		}
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath(defaultConfigDir())
		if err := v.ReadInConfig(); err != nil {
			var nf viper.ConfigFileNotFoundError
			if !errors.As(err, &nf) {
				return c, err
			}
		}
	}
	if err := v.Unmarshal(&c); err != nil {
		return c, err
	}
	return c, nil
}

func (c Config) ValidateAdminClient(checkFiles bool) error {
	switch c.Admin.Transport {
	case "tcp":
		parsed, err := url.Parse(c.Admin.URL)
		if err != nil || parsed.Host == "" {
			return errors.New("admin.url must be an absolute HTTP(S) URL")
		}
		if parsed.Scheme == "http" {
			if !isLoopbackHost(parsed.Hostname()) {
				return errors.New("insecure admin URL must use loopback")
			}
		} else if parsed.Scheme == "https" {
			if c.Admin.TLS.CertificateFile == "" || c.Admin.TLS.PrivateKeyFile == "" || c.Admin.TLS.ServerCAFile == "" || c.Admin.TLS.ServerName == "" {
				return errors.New("HTTPS admin client requires certificate_file, private_key_file, server_ca_file, and server_name")
			}
			if checkFiles {
				if err = checkKeyPair("admin client TLS", c.Admin.TLS.CertificateFile, c.Admin.TLS.PrivateKeyFile); err != nil {
					return err
				}
				if err = checkCAFile("admin server CA", c.Admin.TLS.ServerCAFile); err != nil {
					return err
				}
			}
		} else {
			return errors.New("admin.url scheme must be http or https")
		}
	case "unix":
		if runtime.GOOS == "windows" {
			return errors.New("unix admin client transport is not supported on Windows")
		}
		if c.Admin.Socket == "" || !filepath.IsAbs(c.Admin.Socket) {
			return errors.New("admin.socket must be an absolute path")
		}
	case "named_pipe":
		if runtime.GOOS != "windows" {
			return errors.New("named_pipe admin client transport is only supported on Windows")
		}
		if !strings.HasPrefix(strings.ToLower(c.Admin.Pipe), `\\.\pipe\`) {
			return errors.New(`admin.pipe must start with \\.\pipe\`)
		}
	default:
		return errors.New("admin.transport must be tcp, unix, or named_pipe")
	}
	return nil
}

func (c Config) Validate(checkFiles bool) error {
	if !oneOf(c.Database.Driver, "sqlite", "postgres") {
		return fmt.Errorf("database.driver must be sqlite or postgres")
	}
	if c.Database.Driver == "sqlite" && c.Database.DSN == "" {
		return errors.New("database.dsn is required for sqlite")
	}
	if c.Database.Driver == "postgres" {
		if !validEnvName(c.Database.DSNEnv) {
			return errors.New("database.dsn_env must name the PostgreSQL connection-string environment variable")
		}
		if c.Database.Postgres.MaxConnections < 1 || c.Database.Postgres.MinConnections < 0 || c.Database.Postgres.MinConnections > c.Database.Postgres.MaxConnections || c.Database.Postgres.MaxConnLifetime <= 0 {
			return errors.New("invalid database.postgres pool configuration")
		}
		if checkFiles && os.Getenv(c.Database.DSNEnv) == "" {
			return fmt.Errorf("environment variable %s is required", c.Database.DSNEnv)
		}
		if checkFiles {
			dsnURL, err := url.Parse(os.Getenv(c.Database.DSNEnv))
			if err != nil || !oneOf(dsnURL.Scheme, "postgres", "postgresql") || dsnURL.Host == "" {
				return fmt.Errorf("%s must contain an absolute PostgreSQL URL", c.Database.DSNEnv)
			}
			if dsnURL.Query().Get("sslmode") != "verify-full" {
				return errors.New("production PostgreSQL requires sslmode=verify-full")
			}
		}
		if c.Backup.Continuous.Enabled {
			return errors.New("Litestream continuous backup is SQLite-only; use PostgreSQL-native managed backups")
		}
	}
	if c.Database.MigrationBackupMaxAge <= 0 {
		return errors.New("database.migration_backup_max_age must be positive")
	}
	if !oneOf(strings.ToUpper(c.Database.SQLite.JournalMode), "WAL", "DELETE") {
		return errors.New("database.sqlite.journal_mode must be WAL or DELETE")
	}
	if !oneOf(strings.ToUpper(c.Database.SQLite.Synchronous), "FULL", "NORMAL", "EXTRA") {
		return errors.New("database.sqlite.synchronous must be FULL, NORMAL, or EXTRA")
	}
	if c.Trial.DefaultDuration <= 0 {
		return errors.New("trial.default_duration must be positive")
	}
	if !validEnvName(c.Trial.PepperEnv) {
		return errors.New("trial.pepper_env must name an environment variable")
	}
	if !validEnvName(c.Activation.PepperEnv) {
		return errors.New("activation.pepper_env must name an environment variable")
	}
	if !validEnvName(c.RateLimit.PepperEnv) {
		return errors.New("rate_limit.pepper_env must name an environment variable")
	}
	if c.RateLimit.Window <= 0 || c.RateLimit.Retention < c.RateLimit.Window {
		return errors.New("rate_limit.window must be positive and retention must be at least one window")
	}
	for name, value := range map[string]int{"trial.per_ip": c.RateLimit.Trial.PerIP, "trial.per_subject": c.RateLimit.Trial.PerSubject, "trial.per_product": c.RateLimit.Trial.PerProduct, "activation.per_ip": c.RateLimit.Activation.PerIP, "activation.per_code": c.RateLimit.Activation.PerCode, "status.per_ip": c.RateLimit.Status.PerIP} {
		if value <= 0 {
			return fmt.Errorf("rate_limit.%s must be positive", name)
		}
	}
	if c.HTTP.MaxBodyBytes < 1024 {
		return errors.New("http.max_body_bytes must be at least 1024")
	}
	if c.HTTP.MaxHeaderBytes < 1024 || c.HTTP.MaxHeaderBytes > 1048576 {
		return errors.New("http.max_header_bytes must be between 1024 and 1048576")
	}
	if !oneOf(c.Logging.Format, "json", "text") || !oneOf(strings.ToLower(c.Logging.Level), "debug", "info", "warn", "error") {
		return errors.New("logging format or level is invalid")
	}
	if c.Logging.Output != "stdout" && c.Logging.Output != "stderr" {
		if !filepath.IsAbs(c.Logging.Output) {
			return errors.New("logging.output file must be an absolute path")
		}
		if c.Logging.File.MaxSizeBytes < 1024 || c.Logging.File.MaxBackups < 1 || c.Logging.File.MaxAge <= 0 {
			return errors.New("file logging requires positive bounded rotation and retention settings")
		}
	}
	if c.Archive.PaidLicenceAckPolicy != "strict" && c.Archive.PaidLicenceAckPolicy != "asynchronous" {
		return errors.New("archive.paid_licence_ack_policy must be strict or asynchronous")
	}
	if !oneOf(c.Archive.Provider, "filesystem", "s3", "disabled") {
		return errors.New("archive.provider must be filesystem, s3, or disabled")
	}
	if c.Archive.Provider == "s3" {
		if c.Archive.S3.Bucket == "" || c.Archive.S3.Region == "" {
			return errors.New("archive.s3.bucket and region are required")
		}
		if strings.Contains(c.Archive.S3.Prefix, "..") {
			return errors.New("archive.s3.prefix must not contain '..'")
		}
		if c.Archive.S3.Endpoint != "" {
			if u, err := url.Parse(c.Archive.S3.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New("archive.s3.endpoint must be an absolute HTTPS URL")
			}
		}
		if c.Archive.S3.Encryption != "sse-kms" || c.Archive.S3.KMSKeyID == "" {
			return errors.New("archive S3 requires sse-kms encryption and kms_key_id")
		}
		if !oneOf(c.Archive.S3.ObjectLockMode, "GOVERNANCE", "COMPLIANCE") || c.Archive.S3.ObjectLockFor <= 0 {
			return errors.New("archive S3 requires GOVERNANCE or COMPLIANCE object lock with positive retention")
		}
	}
	if !oneOf(c.Signer.Provider, "file", "aws-kms") {
		return errors.New("signer.provider must be file or aws-kms")
	}
	if c.Signer.Provider == "aws-kms" {
		if c.Signer.KMS.KeyID == "" || c.Signer.KMS.Region == "" || c.Signer.IssuerCertificateFile == "" {
			return errors.New("AWS KMS signer requires key_id, region, and issuer_certificate_file")
		}
		if c.Signer.KMS.Endpoint != "" {
			if u, err := url.Parse(c.Signer.KMS.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New("signer.kms.endpoint must be an absolute HTTPS URL")
			}
		}
	}
	if err := c.validateContinuousBackup(checkFiles); err != nil {
		return err
	}
	if err := c.validateRecoveryDrill(); err != nil {
		return err
	}
	if err := c.validatePublicTransport(checkFiles); err != nil {
		return err
	}
	if err := c.validateAdminTransport(checkFiles); err != nil {
		return err
	}
	if checkFiles {
		paths := map[string]string{"root public key": c.Signer.RootPublicKeyFile}
		if c.Signer.Provider == "file" {
			paths["signer key directory"] = c.SignerKeyDirectory()
		} else {
			paths["issuer certificate"] = c.Signer.IssuerCertificateFile
		}
		for label, path := range paths {
			if path == "" {
				return fmt.Errorf("%s path is required", label)
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
		activationPepper, secretErr := secretvalue.String(c.Activation.PepperEnv)
		if secretErr != nil {
			return secretErr
		}
		trialPepper, secretErr := secretvalue.String(c.Trial.PepperEnv)
		if secretErr != nil {
			return secretErr
		}
		rateLimitPepper, secretErr := secretvalue.String(c.RateLimit.PepperEnv)
		if secretErr != nil {
			return secretErr
		}
		if len(trialPepper) < 16 {
			return fmt.Errorf("%s must contain at least 16 bytes", c.Trial.PepperEnv)
		}
		if len(activationPepper) < 32 {
			return fmt.Errorf("%s must contain at least 32 bytes", c.Activation.PepperEnv)
		}
		if activationPepper == trialPepper {
			return errors.New("activation and trial peppers must be distinct")
		}
		if len(rateLimitPepper) < 32 {
			return fmt.Errorf("%s must contain at least 32 bytes", c.RateLimit.PepperEnv)
		}
		if rateLimitPepper == trialPepper || rateLimitPepper == activationPepper {
			return errors.New("rate-limit, activation, and trial peppers must be distinct")
		}
	}
	return nil
}

func (c Config) validateRecoveryDrill() error {
	d := c.RecoveryDrill
	if !oneOf(d.Mode, "simulation", "credentialed") {
		return errors.New("recovery_drill.mode must be simulation or credentialed")
	}
	if d.RequireReverseProxy && d.ReverseProxyURL == "" {
		return errors.New("recovery_drill.require_reverse_proxy requires reverse_proxy_url")
	}
	if d.ReverseProxyURL != "" {
		u, err := url.Parse(d.ReverseProxyURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("recovery_drill.reverse_proxy_url must be an absolute credential-free HTTPS origin")
		}
	}
	if !d.Enabled {
		if d.Required {
			return errors.New("recovery_drill.required requires recovery_drill.enabled")
		}
		return nil
	}
	if c.Database.Driver != "sqlite" {
		return errors.New("scheduled recovery drills currently require the SQLite/Litestream deployment profile")
	}
	if d.Mode == "credentialed" && (!c.Backup.Continuous.Enabled || c.Archive.Provider == "disabled") {
		return errors.New("credentialed recovery drills require continuous backup and an immutable archive")
	}
	if d.ScheduleInterval <= 0 || d.MaxReportAge < d.ScheduleInterval || d.Timeout <= 0 || d.RPOObjective <= 0 || d.RTOObjective <= 0 || d.ReportRetention < d.MaxReportAge {
		return errors.New("recovery drill schedule, age, timeout, RPO/RTO and retention durations are inconsistent")
	}
	if d.ReportDirectory == "" || !filepath.IsAbs(d.ReportDirectory) {
		return errors.New("recovery_drill.report_directory must be an absolute path")
	}
	if d.MaxMemoryBytes < 64*1024*1024 || d.MaxGoroutines < 1 || d.MaxTemporaryStorageBytes < 1024*1024 {
		return errors.New("recovery drill resource limits are too small")
	}
	return nil
}

func (c Config) validateContinuousBackup(checkEnvironment bool) error {
	b := c.Backup.Continuous
	if !b.Enabled {
		return nil
	}
	if b.Binary == "" {
		return errors.New("backup.continuous.binary is required")
	}
	if b.ReplicaURL == "" {
		return errors.New("backup.continuous.replica_url is required")
	}
	u, err := url.Parse(b.ReplicaURL)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return errors.New("backup.continuous.replica_url must be an s3:// bucket URL")
	}
	if u.User != nil {
		return errors.New("backup.continuous.replica_url must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("backup.continuous.replica_url must not contain query parameters or a fragment; use explicit S3 settings")
	}
	for name, value := range map[string]time.Duration{
		"sync_interval": b.SyncInterval, "snapshot_interval": b.SnapshotInterval,
		"retention": b.Retention, "validation_interval": b.ValidationInterval,
		"health_check_interval": b.HealthCheckInterval, "max_backup_age": b.MaxBackupAge,
		"shutdown_timeout": b.ShutdownTimeout,
	} {
		if value <= 0 {
			return fmt.Errorf("backup.continuous.%s must be positive", name)
		}
	}
	if b.Retention < b.SnapshotInterval {
		return errors.New("backup.continuous.retention must be at least snapshot_interval")
	}
	if b.MaxBackupAge < b.SyncInterval {
		return errors.New("backup.continuous.max_backup_age must be at least sync_interval")
	}
	if b.S3.Endpoint != "" {
		e, parseErr := url.Parse(b.S3.Endpoint)
		if parseErr != nil || e.Scheme != "https" || e.Host == "" {
			return errors.New("backup.continuous.s3.endpoint must be an absolute HTTPS URL")
		}
	}
	switch b.S3.Encryption.Mode {
	case "sse-kms":
		if b.S3.Encryption.CustomerKeyEnv != "" {
			return errors.New("SSE-KMS and SSE-C settings are mutually exclusive")
		}
		if (b.S3.Encryption.KMSKeyID == "") == (b.S3.Encryption.KMSKeyIDEnv == "") {
			return errors.New("SSE-KMS requires exactly one of kms_key_id or kms_key_id_env")
		}
		if b.S3.Encryption.KMSKeyIDEnv != "" {
			if !validEnvName(b.S3.Encryption.KMSKeyIDEnv) {
				return errors.New("backup continuous KMS key environment variable name is invalid")
			}
			if checkEnvironment && os.Getenv(b.S3.Encryption.KMSKeyIDEnv) == "" {
				return fmt.Errorf("environment variable %s is required for SSE-KMS", b.S3.Encryption.KMSKeyIDEnv)
			}
		}
	case "sse-c":
		if b.S3.Encryption.KMSKeyID != "" || b.S3.Encryption.KMSKeyIDEnv != "" {
			return errors.New("SSE-C and SSE-KMS settings are mutually exclusive")
		}
		if !validEnvName(b.S3.Encryption.CustomerKeyEnv) {
			return errors.New("SSE-C requires a valid customer_key_env")
		}
		if checkEnvironment {
			encoded := os.Getenv(b.S3.Encryption.CustomerKeyEnv)
			if encoded == "" {
				return fmt.Errorf("environment variable %s is required for SSE-C", b.S3.Encryption.CustomerKeyEnv)
			}
			key, decodeErr := base64.StdEncoding.DecodeString(encoded)
			if decodeErr != nil || len(key) != 32 {
				return fmt.Errorf("environment variable %s must contain a base64-encoded 256-bit SSE-C key", b.S3.Encryption.CustomerKeyEnv)
			}
		}
	default:
		return errors.New("backup.continuous.s3.encryption.mode must be sse-kms or sse-c; unencrypted S3 backup is not allowed")
	}
	return nil
}

func validEnvName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (c Config) validatePublicTransport(checkFiles bool) error {
	if c.TLS.MinVersion != "1.3" {
		return errors.New("tls.min_version must be 1.3")
	}
	if c.TLS.Enabled && c.TLS.ReverseProxy.Enabled {
		return errors.New("tls.enabled and tls.reverse_proxy.enabled are mutually exclusive")
	}
	if c.TLS.Enabled {
		if c.TLS.CertificateFile == "" || c.TLS.PrivateKeyFile == "" {
			return errors.New("TLS certificate_file and private_key_file are required")
		}
		if checkFiles {
			if err := checkKeyPair("public TLS", c.TLS.CertificateFile, c.TLS.PrivateKeyFile); err != nil {
				return err
			}
		}
		return nil
	}
	if c.TLS.ReverseProxy.Enabled {
		if len(c.TLS.ReverseProxy.TrustedCIDRs) == 0 {
			return errors.New("tls.reverse_proxy.trusted_cidrs must not be empty")
		}
		for _, cidr := range c.TLS.ReverseProxy.TrustedCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid trusted reverse-proxy CIDR %q: %w", cidr, err)
			}
		}
		return nil
	}
	if !isLoopback(c.Server.PublicListen) {
		return errors.New("insecure public listener must use loopback; enable TLS or explicitly configure a trusted reverse proxy")
	}
	return nil
}

func (c Config) validateAdminTransport(checkFiles bool) error {
	switch c.Server.AdminTransport {
	case "tcp":
		if c.AdminTLS.Enabled {
			if c.AdminTLS.CertificateFile == "" || c.AdminTLS.PrivateKeyFile == "" || c.AdminTLS.ClientCAFile == "" {
				return errors.New("admin mTLS requires certificate_file, private_key_file, and client_ca_file")
			}
			if len(c.AdminAuthorization.Identities) == 0 {
				return errors.New("admin mTLS requires at least one admin_authorization identity")
			}
			if checkFiles {
				if err := checkKeyPair("admin TLS", c.AdminTLS.CertificateFile, c.AdminTLS.PrivateKeyFile); err != nil {
					return err
				}
				if err := checkCAFile("admin client CA", c.AdminTLS.ClientCAFile); err != nil {
					return err
				}
			}
		} else if !c.Server.AllowInsecureAdmin || !isLoopback(c.Server.AdminListen) {
			return errors.New("TCP admin requires mTLS; insecure loopback requires server.allow_insecure_admin=true")
		}
	case "unix":
		if runtime.GOOS == "windows" {
			return errors.New("unix admin transport is not supported on Windows")
		}
		if c.Server.AdminSocket == "" || !filepath.IsAbs(c.Server.AdminSocket) {
			return errors.New("server.admin_socket must be an absolute path")
		}
		mode, err := strconv.ParseUint(c.Server.AdminSocketMode, 8, 32)
		if err != nil || mode&^0o777 != 0 || mode&0o007 != 0 {
			return errors.New("server.admin_socket_mode must be an octal mode that grants no access to other users")
		}
	case "named_pipe":
		if runtime.GOOS != "windows" {
			return errors.New("named_pipe admin transport is only supported on Windows")
		}
		if !strings.HasPrefix(strings.ToLower(c.Server.AdminPipe), `\\.\pipe\`) {
			return errors.New(`server.admin_pipe must start with \\.\pipe\`)
		}
		if c.Server.AdminPipeSDDL == "" {
			return errors.New("server.admin_pipe_sddl is required")
		}
		if err := admintransport.ValidatePipeSDDL(c.Server.AdminPipeSDDL); err != nil {
			return fmt.Errorf("invalid server.admin_pipe_sddl: %w", err)
		}
	default:
		return errors.New("server.admin_transport must be tcp, unix, or named_pipe")
	}
	seenIdentities := map[string]string{}
	for _, identity := range c.AdminAuthorization.Identities {
		if strings.TrimSpace(identity.Match) == "" {
			return errors.New("admin authorization identity must not be empty")
		}
		normalized := strings.ToLower(identity.Match)
		if previous, ok := seenIdentities[normalized]; ok {
			return fmt.Errorf("admin identities %q and %q differ only by case", previous, identity.Match)
		}
		seenIdentities[normalized] = identity.Match
		for _, role := range identity.Roles {
			if !oneOf(role, "viewer", "operator", "revoker", "admin") {
				return fmt.Errorf("unknown admin role %q for identity %q", role, identity.Match)
			}
		}
	}
	return nil
}

func checkKeyPair(label, certificate, key string) error {
	if _, err := tls.LoadX509KeyPair(certificate, key); err != nil {
		return fmt.Errorf("%s certificate/key: %w", label, err)
	}
	return nil
}
func checkCAFile(label, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return fmt.Errorf("%s contains no valid PEM certificates", label)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, v := range allowed {
		if value == v {
			return true
		}
	}
	return false
}

func setDefaults(v *viper.Viper, c Config) {
	v.SetDefault("server.public_listen", c.Server.PublicListen)
	v.SetDefault("server.admin_transport", c.Server.AdminTransport)
	v.SetDefault("server.admin_listen", c.Server.AdminListen)
	v.SetDefault("server.admin_socket", c.Server.AdminSocket)
	v.SetDefault("server.admin_socket_mode", c.Server.AdminSocketMode)
	v.SetDefault("server.admin_pipe", c.Server.AdminPipe)
	v.SetDefault("server.admin_pipe_sddl", c.Server.AdminPipeSDDL)
	v.SetDefault("server.allow_insecure_admin", c.Server.AllowInsecureAdmin)
	v.SetDefault("tls.min_version", c.TLS.MinVersion)
	v.SetDefault("database.driver", c.Database.Driver)
	v.SetDefault("database.dsn", c.Database.DSN)
	v.SetDefault("database.dsn_env", c.Database.DSNEnv)
	v.SetDefault("database.migration_backup_max_age", c.Database.MigrationBackupMaxAge)
	v.SetDefault("database.sqlite.journal_mode", c.Database.SQLite.JournalMode)
	v.SetDefault("database.sqlite.synchronous", c.Database.SQLite.Synchronous)
	v.SetDefault("database.sqlite.foreign_keys", c.Database.SQLite.ForeignKeys)
	v.SetDefault("database.sqlite.busy_timeout", c.Database.SQLite.BusyTimeout)
	v.SetDefault("database.postgres.max_connections", c.Database.Postgres.MaxConnections)
	v.SetDefault("database.postgres.min_connections", c.Database.Postgres.MinConnections)
	v.SetDefault("database.postgres.max_conn_lifetime", c.Database.Postgres.MaxConnLifetime)
	v.SetDefault("signer.provider", c.Signer.Provider)
	v.SetDefault("signer.root_public_key_file", c.Signer.RootPublicKeyFile)
	v.SetDefault("signer.key_directory", c.Signer.KeyDirectory)
	v.SetDefault("signer.private_key_file", c.Signer.PrivateKeyFile)
	v.SetDefault("signer.issuer_certificate_file", c.Signer.IssuerCertificateFile)
	v.SetDefault("signer.kms.key_id", c.Signer.KMS.KeyID)
	v.SetDefault("signer.kms.region", c.Signer.KMS.Region)
	v.SetDefault("signer.kms.endpoint", c.Signer.KMS.Endpoint)
	v.SetDefault("archive.provider", c.Archive.Provider)
	v.SetDefault("archive.directory", c.Archive.Directory)
	v.SetDefault("archive.paid_licence_ack_policy", c.Archive.PaidLicenceAckPolicy)
	v.SetDefault("archive.s3.bucket", c.Archive.S3.Bucket)
	v.SetDefault("archive.s3.prefix", c.Archive.S3.Prefix)
	v.SetDefault("archive.s3.region", c.Archive.S3.Region)
	v.SetDefault("archive.s3.endpoint", c.Archive.S3.Endpoint)
	v.SetDefault("archive.s3.force_path_style", c.Archive.S3.ForcePathStyle)
	v.SetDefault("archive.s3.encryption", c.Archive.S3.Encryption)
	v.SetDefault("archive.s3.kms_key_id", c.Archive.S3.KMSKeyID)
	v.SetDefault("archive.s3.object_lock_mode", c.Archive.S3.ObjectLockMode)
	v.SetDefault("archive.s3.object_lock_for", c.Archive.S3.ObjectLockFor)
	v.SetDefault("backup.continuous.enabled", c.Backup.Continuous.Enabled)
	v.SetDefault("backup.continuous.required", c.Backup.Continuous.Required)
	v.SetDefault("backup.continuous.binary", c.Backup.Continuous.Binary)
	v.SetDefault("backup.continuous.config_file", c.Backup.Continuous.ConfigFile)
	v.SetDefault("backup.continuous.replica_url", c.Backup.Continuous.ReplicaURL)
	v.SetDefault("backup.continuous.sync_interval", c.Backup.Continuous.SyncInterval)
	v.SetDefault("backup.continuous.snapshot_interval", c.Backup.Continuous.SnapshotInterval)
	v.SetDefault("backup.continuous.retention", c.Backup.Continuous.Retention)
	v.SetDefault("backup.continuous.validation_interval", c.Backup.Continuous.ValidationInterval)
	v.SetDefault("backup.continuous.health_check_interval", c.Backup.Continuous.HealthCheckInterval)
	v.SetDefault("backup.continuous.max_backup_age", c.Backup.Continuous.MaxBackupAge)
	v.SetDefault("backup.continuous.shutdown_timeout", c.Backup.Continuous.ShutdownTimeout)
	v.SetDefault("backup.continuous.s3.region", c.Backup.Continuous.S3.Region)
	v.SetDefault("backup.continuous.s3.endpoint", c.Backup.Continuous.S3.Endpoint)
	v.SetDefault("backup.continuous.s3.force_path_style", c.Backup.Continuous.S3.ForcePathStyle)
	v.SetDefault("backup.continuous.s3.encryption.mode", c.Backup.Continuous.S3.Encryption.Mode)
	v.SetDefault("backup.continuous.s3.encryption.kms_key_id", c.Backup.Continuous.S3.Encryption.KMSKeyID)
	v.SetDefault("backup.continuous.s3.encryption.kms_key_id_env", c.Backup.Continuous.S3.Encryption.KMSKeyIDEnv)
	v.SetDefault("backup.continuous.s3.encryption.customer_key_env", c.Backup.Continuous.S3.Encryption.CustomerKeyEnv)
	v.SetDefault("recovery_drill.enabled", c.RecoveryDrill.Enabled)
	v.SetDefault("recovery_drill.required", c.RecoveryDrill.Required)
	v.SetDefault("recovery_drill.mode", c.RecoveryDrill.Mode)
	v.SetDefault("recovery_drill.schedule_interval", c.RecoveryDrill.ScheduleInterval)
	v.SetDefault("recovery_drill.max_report_age", c.RecoveryDrill.MaxReportAge)
	v.SetDefault("recovery_drill.timeout", c.RecoveryDrill.Timeout)
	v.SetDefault("recovery_drill.rpo_objective", c.RecoveryDrill.RPOObjective)
	v.SetDefault("recovery_drill.rto_objective", c.RecoveryDrill.RTOObjective)
	v.SetDefault("recovery_drill.report_directory", c.RecoveryDrill.ReportDirectory)
	v.SetDefault("recovery_drill.report_retention", c.RecoveryDrill.ReportRetention)
	v.SetDefault("recovery_drill.reverse_proxy_url", c.RecoveryDrill.ReverseProxyURL)
	v.SetDefault("recovery_drill.require_reverse_proxy", c.RecoveryDrill.RequireReverseProxy)
	v.SetDefault("recovery_drill.max_memory_bytes", c.RecoveryDrill.MaxMemoryBytes)
	v.SetDefault("recovery_drill.max_goroutines", c.RecoveryDrill.MaxGoroutines)
	v.SetDefault("recovery_drill.max_temporary_storage_bytes", c.RecoveryDrill.MaxTemporaryStorageBytes)
	v.SetDefault("trial.default_duration", c.Trial.DefaultDuration)
	v.SetDefault("trial.pepper_env", c.Trial.PepperEnv)
	v.SetDefault("activation.pepper_env", c.Activation.PepperEnv)
	v.SetDefault("rate_limit.pepper_env", c.RateLimit.PepperEnv)
	v.SetDefault("rate_limit.window", c.RateLimit.Window)
	v.SetDefault("rate_limit.retention", c.RateLimit.Retention)
	v.SetDefault("rate_limit.trial.per_ip", c.RateLimit.Trial.PerIP)
	v.SetDefault("rate_limit.trial.per_subject", c.RateLimit.Trial.PerSubject)
	v.SetDefault("rate_limit.trial.per_product", c.RateLimit.Trial.PerProduct)
	v.SetDefault("rate_limit.activation.per_ip", c.RateLimit.Activation.PerIP)
	v.SetDefault("rate_limit.activation.per_code", c.RateLimit.Activation.PerCode)
	v.SetDefault("rate_limit.status.per_ip", c.RateLimit.Status.PerIP)
	v.SetDefault("http.max_body_bytes", c.HTTP.MaxBodyBytes)
	v.SetDefault("http.max_header_bytes", c.HTTP.MaxHeaderBytes)
	v.SetDefault("http.read_header_timeout", c.HTTP.ReadHeaderTimeout)
	v.SetDefault("http.read_timeout", c.HTTP.ReadTimeout)
	v.SetDefault("http.write_timeout", c.HTTP.WriteTimeout)
	v.SetDefault("http.idle_timeout", c.HTTP.IdleTimeout)
	v.SetDefault("logging.format", c.Logging.Format)
	v.SetDefault("logging.level", c.Logging.Level)
	v.SetDefault("logging.output", c.Logging.Output)
	v.SetDefault("logging.file.max_size_bytes", c.Logging.File.MaxSizeBytes)
	v.SetDefault("logging.file.max_backups", c.Logging.File.MaxBackups)
	v.SetDefault("logging.file.max_age", c.Logging.File.MaxAge)
	v.SetDefault("admin.url", c.Admin.URL)
	v.SetDefault("admin.transport", c.Admin.Transport)
	v.SetDefault("admin.socket", c.Admin.Socket)
	v.SetDefault("admin.pipe", c.Admin.Pipe)
}

func (c Config) SignerKeyDirectory() string {
	if c.Signer.KeyDirectory != "" {
		return c.Signer.KeyDirectory
	}
	return filepath.Dir(c.Signer.PrivateKeyFile)
}

func (c Config) DatabaseDSN() string {
	if c.Database.Driver == "postgres" {
		return os.Getenv(c.Database.DSNEnv)
	}
	return c.Database.DSN
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackHost(host)
}
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

func defaultDataPath() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "licd", "licensing.db")
		}
	}
	return "/var/lib/licd/licensing.db"
}

func defaultConfigDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "licd")
		}
	}
	return "/etc/licd"
}

func defaultAdminTransport() string {
	if runtime.GOOS == "windows" {
		return "named_pipe"
	}
	return "unix"
}
func defaultAdminSocket() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/run/licd/admin.sock"
}
