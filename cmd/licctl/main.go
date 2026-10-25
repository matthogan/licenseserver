package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/adminclient"
	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	archives3 "github.com/matthogan/licenceserver/internal/archive/s3"
	"github.com/matthogan/licenceserver/internal/buildinfo"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	dataexporter "github.com/matthogan/licenceserver/internal/dataexport"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/issuer"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/logicalbackup"
	"github.com/matthogan/licenceserver/internal/recovery"
	"github.com/matthogan/licenceserver/internal/recoverydrill"
	"github.com/matthogan/licenceserver/internal/signing"
	postgresrepo "github.com/matthogan/licenceserver/internal/storage/postgres"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
	"github.com/spf13/cobra"
)

var opts struct {
	config, server string
	json           bool
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func rootCmd() *cobra.Command {
	r := &cobra.Command{Use: "licctl", Short: "Administration CLI for licd", SilenceUsage: true}
	r.PersistentFlags().StringVar(&opts.config, "config", "", "configuration file")
	r.PersistentFlags().StringVar(&opts.server, "server", "", "admin API base URL")
	r.PersistentFlags().BoolVar(&opts.json, "json", false, "print machine-readable JSON")
	r.AddCommand(healthCmd(), maintenanceCmd(), productCmd(), trialCmd(), licenceCmd(), activationCmd(), issuerCmd(), rootLifecycleCmd(), archiveCmd(), backupCmd(), restoreCmd(), recoveryDrillCmd(), dbCmd(), auditCmd(), dataCmd(), versionCmd())
	return r
}
func getClient() (*adminclient.Client, error) {
	if opts.server != "" {
		c := config.Defaults()
		c.Admin.Transport = "tcp"
		c.Admin.URL = opts.server
		if err := c.ValidateAdminClient(false); err != nil {
			return nil, fmt.Errorf("--server: %w; use --config for mTLS", err)
		}
		return adminclient.NewForConfig(c)
	}
	c, err := config.LoadClient(opts.config)
	if err != nil {
		return nil, err
	}
	return adminclient.NewForConfig(c)
}
func call(ctx context.Context, method, path string, in, out any) error {
	c, err := getClient()
	if err != nil {
		return err
	}
	return c.Do(ctx, method, path, in, out)
}
func printValue(v any) error {
	if opts.json {
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func healthCmd() *cobra.Command {
	return &cobra.Command{Use: "health", Short: "Check server readiness", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/health/ready", nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
}

func maintenanceCmd() *cobra.Command {
	c := &cobra.Command{Use: "maintenance", Short: "Inspect and control persistent maintenance mode"}
	c.AddCommand(&cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var state domain.MaintenanceState
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/maintenance", nil, &state); err != nil {
			return err
		}
		return printValue(state)
	}})
	var enableReason string
	enable := &cobra.Command{Use: "enable", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var state domain.MaintenanceState
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/maintenance", map[string]any{"enabled": true, "reason": enableReason}, &state); err != nil {
			return err
		}
		return printValue(state)
	}}
	enable.Flags().StringVar(&enableReason, "reason", "", "operational reason (required)")
	_ = enable.MarkFlagRequired("reason")
	var disableReason string
	disable := &cobra.Command{Use: "disable", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var state domain.MaintenanceState
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/maintenance", map[string]any{"enabled": false, "reason": disableReason}, &state); err != nil {
			return err
		}
		return printValue(state)
	}}
	disable.Flags().StringVar(&disableReason, "reason", "", "completion reason (required)")
	_ = disable.MarkFlagRequired("reason")
	c.AddCommand(enable, disable)
	return c
}

func productCmd() *cobra.Command {
	c := &cobra.Command{Use: "product", Short: "Manage products"}
	c.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/products", nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}})
	c.AddCommand(&cobra.Command{Use: "show PRODUCT_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/products/"+args[0], nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}})
	var name string
	var trial time.Duration
	var active bool
	create := &cobra.Command{Use: "create PRODUCT_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		req := domain.Product{ProductID: args[0], DisplayName: name, DefaultTrialSeconds: int64(trial / time.Second), Active: active}
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/products", req, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	create.Flags().StringVar(&name, "display-name", "", "display name (required)")
	_ = create.MarkFlagRequired("display-name")
	create.Flags().DurationVar(&trial, "trial-duration", 30*24*time.Hour, "default trial duration")
	create.Flags().BoolVar(&active, "active", true, "allow issuance")
	var updateName string
	var updateTrial time.Duration
	var updateActive bool
	update := &cobra.Command{Use: "update PRODUCT_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var req domain.ProductUpdate
		if cmd.Flags().Changed("display-name") {
			req.DisplayName = &updateName
		}
		if cmd.Flags().Changed("trial-duration") {
			seconds := int64(updateTrial / time.Second)
			req.DefaultTrialSeconds = &seconds
		}
		if cmd.Flags().Changed("active") {
			req.Active = &updateActive
		}
		var v any
		if err := call(cmd.Context(), http.MethodPatch, "/admin/v1/products/"+url.PathEscape(args[0]), req, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	update.Flags().StringVar(&updateName, "display-name", "", "new display name")
	update.Flags().DurationVar(&updateTrial, "trial-duration", 0, "new default trial duration")
	update.Flags().BoolVar(&updateActive, "active", true, "allow issuance")
	c.AddCommand(create, update)
	return c
}

func trialCmd() *cobra.Command {
	var installID, publicURL, output string
	c := &cobra.Command{Use: "trial", Short: "Trial operations"}
	issue := &cobra.Command{Use: "issue PRODUCT_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		req := licensing.IssueTrialRequest{ProductID: args[0], InstallID: installID}
		base := publicURL
		if base == "" {
			base = "http://127.0.0.1:9443"
		}
		client := adminclient.New(base)
		var result licensing.IssuedLicence
		if err := client.Do(cmd.Context(), http.MethodPost, "/v1/trials", req, &result); err != nil {
			return err
		}
		if output != "" {
			if err := writeExclusive(output, result.LicenceArtifact, 0o600); err != nil {
				return err
			}
		}
		return printValue(result)
	}}
	issue.Flags().StringVar(&installID, "install-id", "", "random installation ID (required)")
	issue.Flags().StringVar(&publicURL, "public-server", "", "public API base URL")
	issue.Flags().StringVarP(&output, "output", "o", "", "write .lic artifact")
	_ = issue.MarkFlagRequired("install-id")
	show := &cobra.Command{Use: "show TRIAL_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/trials/"+url.PathEscape(args[0]), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	c.AddCommand(issue, show)
	return c
}

func licenceCmd() *cobra.Command {
	c := &cobra.Command{Use: "licence", Aliases: []string{"license"}, Short: "Issue and manage licences"}
	var req licensing.IssueLicenceRequest
	var output string
	issue := &cobra.Command{Use: "issue", RunE: func(cmd *cobra.Command, _ []string) error {
		var result licensing.IssuedLicence
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/licences", req, &result); err != nil {
			return err
		}
		if output != "" {
			if err := writeExclusive(output, result.LicenceArtifact, 0o600); err != nil {
				return err
			}
		}
		return printValue(result)
	}}
	issue.Flags().StringVar(&req.ProductID, "product", "", "product ID")
	issue.Flags().StringVar(&req.LicenceType, "type", "perpetual", "licence type")
	issue.Flags().StringVar(&req.CustomerRef, "customer-ref", "", "opaque customer reference")
	issue.Flags().StringVar(&req.PurchaseRef, "purchase-ref", "", "idempotent purchase reference")
	var maxMajor int
	issue.Flags().IntVar(&maxMajor, "max-major-version", 0, "maximum entitled major version (0 omits)")
	issue.Flags().StringSliceVar(&req.Entitlements, "entitlement", nil, "entitlement (repeatable)")
	issue.Flags().IntVar(&req.SeatCount, "seat-count", 1, "seat count")
	issue.Flags().StringVar(&req.SeatModel, "seat-model", "named_user", "seat model")
	issue.Flags().StringVarP(&output, "output", "o", "", "write .lic artifact")
	_ = issue.MarkFlagRequired("product")
	_ = issue.MarkFlagRequired("purchase-ref")
	original := issue.RunE
	issue.RunE = func(cmd *cobra.Command, args []string) error {
		if maxMajor > 0 {
			req.MaxMajorVersion = &maxMajor
		}
		return original(cmd, args)
	}
	var product string
	var limit int
	list := &cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, _ []string) error {
		path := fmt.Sprintf("/admin/v1/licences?product=%s&limit=%d", product, limit)
		var v any
		if err := call(cmd.Context(), http.MethodGet, path, nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	list.Flags().StringVar(&product, "product", "", "filter by product")
	list.Flags().IntVar(&limit, "limit", 100, "maximum records")
	show := &cobra.Command{Use: "show LICENCE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/licences/"+args[0], nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	var reason, text string
	revoke := &cobra.Command{Use: "revoke LICENCE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/licences/"+args[0]+"/revoke", map[string]string{"reason": reason, "text": text}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	revoke.Flags().StringVar(&reason, "reason", "", "reason code")
	revoke.Flags().StringVar(&text, "text", "", "optional explanation")
	_ = revoke.MarkFlagRequired("reason")
	var rootKey, expectedProduct string
	inspect := &cobra.Command{Use: "inspect FILE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		root, err := signing.ReadPublicKey(rootKey)
		if err != nil {
			return err
		}
		p, err := licencefmt.VerifyArtifact(root, raw, expectedProduct, time.Now().UTC())
		if err != nil {
			return err
		}
		return printValue(p)
	}}
	inspect.Flags().StringVar(&rootKey, "root-public-key", "", "trusted root public key")
	inspect.Flags().StringVar(&expectedProduct, "product", "", "expected product ID")
	_ = inspect.MarkFlagRequired("root-public-key")
	var reissueReason, reissueOutput string
	reissue := &cobra.Command{Use: "reissue LICENCE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var result licensing.IssuedLicence
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/licences/"+url.PathEscape(args[0])+"/reissue", map[string]string{"reason": reissueReason}, &result); err != nil {
			return err
		}
		if reissueOutput != "" {
			if err := writeExclusive(reissueOutput, result.LicenceArtifact, 0o600); err != nil {
				return err
			}
		}
		return printValue(result)
	}}
	reissue.Flags().StringVar(&reissueReason, "reason", "", "reissue reason")
	reissue.Flags().StringVarP(&reissueOutput, "output", "o", "", "write replacement .lic artifact")
	_ = reissue.MarkFlagRequired("reason")
	c.AddCommand(issue, list, show, revoke, inspect, reissue)
	return c
}

func activationCmd() *cobra.Command {
	c := &cobra.Command{Use: "activation", Short: "Create codes and manage installation activations"}
	var max int
	var expiry time.Duration
	create := &cobra.Command{Use: "create LICENCE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var exp *time.Time
		if expiry > 0 {
			t := time.Now().UTC().Add(expiry)
			exp = &t
		}
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/activations", map[string]any{"licence_id": args[0], "max_uses": max, "expires_at": exp}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	create.Flags().IntVar(&max, "max-uses", 1, "maximum redemptions")
	create.Flags().DurationVar(&expiry, "expires-in", 0, "optional expiry duration")
	var publicURL, installationID, idempotencyKey string
	var metadata map[string]string
	redeem := &cobra.Command{Use: "redeem CODE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		base := publicURL
		if base == "" {
			base = "http://127.0.0.1:9443"
		}
		var v any
		req := licensing.RedeemActivationRequest{Code: args[0], InstallationID: installationID, Metadata: metadata}
		if err := adminclient.New(base).DoHeaders(cmd.Context(), http.MethodPost, "/v1/activations", req, &v, map[string]string{"Idempotency-Key": idempotencyKey}); err != nil {
			return err
		}
		return printValue(v)
	}}
	redeem.Flags().StringVar(&publicURL, "public-server", "", "public API base URL")
	redeem.Flags().StringVar(&installationID, "installation-id", "", "stable privacy-preserving installation identifier")
	redeem.Flags().StringVar(&idempotencyKey, "request-id", "", "stable client request ID reused for retries")
	redeem.Flags().StringToStringVar(&metadata, "metadata", nil, "bounded activation metadata key=value")
	_ = redeem.MarkFlagRequired("installation-id")
	_ = redeem.MarkFlagRequired("request-id")

	var licenceFilter, codeFilter string
	var limit int
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List installation activation records", RunE: func(cmd *cobra.Command, _ []string) error {
		query := url.Values{}
		query.Set("licence_id", licenceFilter)
		query.Set("activation_code_id", codeFilter)
		query.Set("limit", fmt.Sprint(limit))
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/activations?"+query.Encode(), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	list.Flags().StringVar(&licenceFilter, "licence", "", "filter by licence ID")
	list.Flags().StringVar(&codeFilter, "code-id", "", "filter by activation code ID")
	list.Flags().IntVar(&limit, "limit", 100, "maximum records")
	show := &cobra.Command{Use: "show ACTIVATION_ID", Args: cobra.ExactArgs(1), Short: "Show an installation activation", RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/activations/"+url.PathEscape(args[0]), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	var revokeReason string
	revoke := &cobra.Command{Use: "revoke ACTIVATION_ID", Args: cobra.ExactArgs(1), Short: "Revoke an installation activation and release capacity", RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/activations/"+url.PathEscape(args[0])+"/revoke", map[string]string{"reason": revokeReason}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	revoke.Flags().StringVar(&revokeReason, "reason", "", "revocation reason")
	_ = revoke.MarkFlagRequired("reason")

	codeCmd := &cobra.Command{Use: "code", Short: "Inspect and revoke activation codes"}
	var codeLicence string
	var codeLimit int
	codeList := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		query := url.Values{}
		query.Set("licence_id", codeLicence)
		query.Set("limit", fmt.Sprint(codeLimit))
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/activation-codes?"+query.Encode(), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	codeList.Flags().StringVar(&codeLicence, "licence", "", "filter by licence ID")
	codeList.Flags().IntVar(&codeLimit, "limit", 100, "maximum records")
	codeShow := &cobra.Command{Use: "show ACTIVATION_CODE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/activation-codes/"+url.PathEscape(args[0]), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	var codeReason string
	codeRevoke := &cobra.Command{Use: "revoke ACTIVATION_CODE_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/activation-codes/"+url.PathEscape(args[0])+"/revoke", map[string]string{"reason": codeReason}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	codeRevoke.Flags().StringVar(&codeReason, "reason", "", "revocation reason")
	_ = codeRevoke.MarkFlagRequired("reason")
	codeCmd.AddCommand(codeList, codeShow, codeRevoke)
	c.AddCommand(create, redeem, list, show, revoke, codeCmd)
	return c
}

func issuerCmd() *cobra.Command {
	c := &cobra.Command{Use: "issuer", Short: "Offline root and issuer key operations"}
	var privateOut, publicOut string
	root := &cobra.Command{Use: "generate-root", RunE: func(*cobra.Command, []string) error {
		if err := ensureAbsent(privateOut, publicOut); err != nil {
			return err
		}
		pub, priv, err := signing.GenerateKey()
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(privateOut), 0o700); err != nil {
			return err
		}
		if err = signing.WriteKey(privateOut, priv, 0o600); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(publicOut), 0o755); err != nil {
			return err
		}
		if err = signing.WriteKey(publicOut, pub, 0o644); err != nil {
			return err
		}
		return printValue(map[string]string{"private_key": privateOut, "public_key": publicOut, "fingerprint": fingerprint(pub)})
	}}
	root.Flags().StringVar(&privateOut, "private-key", "root.key", "private key output")
	root.Flags().StringVar(&publicOut, "public-key", "root.pub", "public key output")
	var rootPrivate, issuerPrivate, certOut, keyID string
	var validity time.Duration
	var products []string
	issue := &cobra.Command{Use: "generate", RunE: func(*cobra.Command, []string) error {
		if err := ensureAbsent(issuerPrivate, certOut); err != nil {
			return err
		}
		rootKey, err := signing.ReadPrivateKey(rootPrivate)
		if err != nil {
			return err
		}
		pub, priv, err := signing.GenerateKey()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Add(-time.Minute)
		payload := licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: keyID, Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(pub), AuthorityNotBefore: now, AuthorityNotAfter: now.Add(validity), Products: products}
		cert, err := licencefmt.CreateIssuerCertificate(rootKey, payload)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(issuerPrivate), 0o700); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(certOut), 0o755); err != nil {
			return err
		}
		if err = signing.WriteKey(issuerPrivate, priv, 0o600); err != nil {
			return err
		}
		if err = os.WriteFile(certOut, []byte(cert+"\n"), 0o644); err != nil {
			return err
		}
		return printValue(map[string]string{"issuer_key": issuerPrivate, "certificate": certOut, "key_id": keyID, "fingerprint": fingerprint(pub)})
	}}
	issue.Flags().StringVar(&rootPrivate, "root-private-key", "", "offline root private key")
	issue.Flags().StringVar(&issuerPrivate, "private-key", "issuer.key", "issuer key output")
	issue.Flags().StringVar(&certOut, "certificate", "issuer.cert", "issuer certificate output")
	issue.Flags().StringVar(&keyID, "key-id", "", "issuer key ID")
	issue.Flags().DurationVar(&validity, "valid-for", 365*24*time.Hour, "issuer authority duration")
	issue.Flags().StringSliceVar(&products, "product", []string{"*"}, "authorised product ID")
	_ = issue.MarkFlagRequired("root-private-key")
	_ = issue.MarkFlagRequired("key-id")
	var rootPublic, certFile string
	verify := &cobra.Command{Use: "verify-cert", RunE: func(*cobra.Command, []string) error {
		root, err := signing.ReadPublicKey(rootPublic)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		p, err := licencefmt.VerifyIssuerCertificate(root, strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		return printValue(p)
	}}
	verify.Flags().StringVar(&rootPublic, "root-public-key", "", "trusted root public key")
	verify.Flags().StringVar(&certFile, "certificate", "", "issuer certificate")
	_ = verify.MarkFlagRequired("root-public-key")
	_ = verify.MarkFlagRequired("certificate")
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List registered issuer keys", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/issuers", nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	show := &cobra.Command{Use: "show ISSUER_KEY_ID", Args: cobra.ExactArgs(1), Short: "Show public issuer metadata", RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/issuers/"+url.PathEscape(args[0]), nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	localFilesCommand := func(use, short, endpoint string, replacesRequired bool) *cobra.Command {
		var privateFile, certificateFile, replaces string
		command := &cobra.Command{Use: use, Args: cobra.NoArgs, Short: short, RunE: func(cmd *cobra.Command, _ []string) error {
			req := issuer.LocalFiles{PrivateKeyFile: privateFile, CertificateFile: certificateFile, Replaces: replaces}
			var v any
			if err := call(cmd.Context(), http.MethodPost, endpoint, req, &v); err != nil {
				return err
			}
			return printValue(v)
		}}
		command.Flags().StringVar(&privateFile, "private-key-file", "", "server-local key path inside signer.key_directory")
		command.Flags().StringVar(&certificateFile, "certificate-file", "", "server-local certificate path inside signer.key_directory")
		_ = command.MarkFlagRequired("private-key-file")
		_ = command.MarkFlagRequired("certificate-file")
		if replacesRequired {
			command.Flags().StringVar(&replaces, "replaces", "", "lost or compromised issuer key ID")
			_ = command.MarkFlagRequired("replaces")
		}
		return command
	}
	register := localFilesCommand("register", "Register a staged server-local issuer", "/admin/v1/issuers/register", false)
	rotate := localFilesCommand("rotate", "Atomically register and activate a new issuer", "/admin/v1/issuers/rotate", false)
	recoverIssuer := localFilesCommand("recover", "Activate a replacement for a lost or compromised issuer", "/admin/v1/issuers/rotate", true)
	activate := &cobra.Command{Use: "activate ISSUER_KEY_ID", Args: cobra.ExactArgs(1), Short: "Activate a staged or retired issuer", RunE: func(cmd *cobra.Command, args []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/issuers/"+url.PathEscape(args[0])+"/activate", struct{}{}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	statusCommand := func(use, short, status string, permitNoActive bool) *cobra.Command {
		var reason, confirm string
		var allowNoActive bool
		command := &cobra.Command{Use: use + " ISSUER_KEY_ID", Args: cobra.ExactArgs(1), Short: short, RunE: func(cmd *cobra.Command, args []string) error {
			if (status == domain.IssuerStatusLost || status == domain.IssuerStatusCompromised) && confirm != args[0] {
				return errors.New("--confirm must exactly match ISSUER_KEY_ID")
			}
			var v any
			req := map[string]any{"status": status, "reason": reason, "allow_no_active": allowNoActive}
			if err := call(cmd.Context(), http.MethodPost, "/admin/v1/issuers/"+url.PathEscape(args[0])+"/status", req, &v); err != nil {
				return err
			}
			return printValue(v)
		}}
		command.Flags().StringVar(&reason, "reason", "", "required lifecycle reason")
		_ = command.MarkFlagRequired("reason")
		if status == domain.IssuerStatusLost || status == domain.IssuerStatusCompromised {
			command.Flags().StringVar(&confirm, "confirm", "", "repeat the issuer key ID to confirm emergency issuance shutdown")
			_ = command.MarkFlagRequired("confirm")
		}
		if permitNoActive {
			command.Flags().BoolVar(&allowNoActive, "allow-no-active", false, "permit retiring the active issuer and stopping issuance")
		}
		return command
	}
	retire := statusCommand("retire", "Retire an issuer from new issuance", domain.IssuerStatusRetired, true)
	markLost := statusCommand("mark-lost", "Mark an inaccessible issuer lost and stop it immediately", domain.IssuerStatusLost, false)
	markCompromised := statusCommand("mark-compromised", "Mark an issuer compromised and stop it immediately", domain.IssuerStatusCompromised, false)
	c.AddCommand(root, issue, verify, list, show, register, activate, rotate, retire, markLost, markCompromised, recoverIssuer)
	return c
}

func rootLifecycleCmd() *cobra.Command {
	c := &cobra.Command{Use: "root", Short: "Offline root-transition and trusted-keyring operations"}
	transition := &cobra.Command{Use: "transition", Short: "Generate, inspect, verify, and administer root transitions"}

	var oldPrivateFile, newPrivateFile, output, transitionID, reason, notBeforeRaw string
	var overlap, installGrace time.Duration
	generate := &cobra.Command{Use: "generate", Args: cobra.NoArgs, Short: "Create an offline dual-signed root-transition artefact", RunE: func(cmd *cobra.Command, _ []string) error {
		if err := ensureAbsent(output); err != nil {
			return err
		}
		oldPrivate, err := signing.ReadPrivateKey(oldPrivateFile)
		if err != nil {
			return fmt.Errorf("read old root private key: %w", err)
		}
		newPrivate, err := signing.ReadPrivateKey(newPrivateFile)
		if err != nil {
			return fmt.Errorf("read new root private key: %w", err)
		}
		created := time.Now().UTC()
		notBefore := created
		if strings.TrimSpace(notBeforeRaw) != "" {
			notBefore, err = time.Parse(time.RFC3339, notBeforeRaw)
			if err != nil {
				return fmt.Errorf("--not-before must be RFC3339: %w", err)
			}
			notBefore = notBefore.UTC()
		}
		if overlap <= 0 || installGrace <= 0 {
			return errors.New("--overlap and --install-grace must be positive")
		}
		artefact, err := licencefmt.CreateRootTransition(oldPrivate, newPrivate, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: transitionID, Algorithm: "Ed25519", CreatedAt: created, NotBefore: notBefore, OverlapUntil: notBefore.Add(overlap), ExpiresAt: notBefore.Add(overlap).Add(installGrace), Reason: reason})
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
			return err
		}
		if err = os.WriteFile(output, []byte(artefact+"\n"), 0o644); err != nil {
			return err
		}
		inspection, _ := licencefmt.InspectRootTransition(artefact)
		return printValue(map[string]any{"artefact": output, "payload": inspection.Payload})
	}}
	generate.Flags().StringVar(&oldPrivateFile, "old-root-private-key", "", "offline old root private key")
	generate.Flags().StringVar(&newPrivateFile, "new-root-private-key", "", "offline new root private key")
	generate.Flags().StringVar(&output, "output", "root-transition.rkt", "transition artefact output")
	generate.Flags().StringVar(&transitionID, "transition-id", "", "unique transition ID")
	generate.Flags().StringVar(&reason, "reason", "", "custody or compromise reason recorded in the signed artefact")
	generate.Flags().StringVar(&notBeforeRaw, "not-before", "", "RFC3339 activation time (default now)")
	generate.Flags().DurationVar(&overlap, "overlap", 30*24*time.Hour, "period in which old and new roots overlap")
	generate.Flags().DurationVar(&installGrace, "install-grace", 7*24*time.Hour, "additional period in which clients may install the transition")
	_ = generate.MarkFlagRequired("old-root-private-key")
	_ = generate.MarkFlagRequired("new-root-private-key")
	_ = generate.MarkFlagRequired("transition-id")
	_ = generate.MarkFlagRequired("reason")

	var artefactFile string
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, Short: "Parse a transition without trusting it", RunE: func(*cobra.Command, []string) error {
		raw, err := os.ReadFile(artefactFile)
		if err != nil {
			return err
		}
		inspection, err := licencefmt.InspectRootTransition(string(raw))
		if err != nil {
			return err
		}
		return printValue(inspection)
	}}
	inspect.Flags().StringVar(&artefactFile, "file", "", "root transition artefact")
	_ = inspect.MarkFlagRequired("file")

	var trustedRootFile, verifyAtRaw string
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, Short: "Verify both signatures and the installation window", RunE: func(*cobra.Command, []string) error {
		trusted, err := signing.ReadPublicKey(trustedRootFile)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(artefactFile)
		if err != nil {
			return err
		}
		at := time.Now().UTC()
		if verifyAtRaw != "" {
			at, err = time.Parse(time.RFC3339, verifyAtRaw)
			if err != nil {
				return fmt.Errorf("--at must be RFC3339: %w", err)
			}
		}
		payload, err := licencefmt.VerifyRootTransition(trusted, string(raw), at)
		if err != nil {
			return err
		}
		return printValue(map[string]any{"status": "valid", "verified_at": at.UTC(), "payload": payload})
	}}
	verify.Flags().StringVar(&artefactFile, "file", "", "root transition artefact")
	verify.Flags().StringVar(&trustedRootFile, "trusted-old-root", "", "currently trusted old root public key")
	verify.Flags().StringVar(&verifyAtRaw, "at", "", "RFC3339 verification time (default now)")
	_ = verify.MarkFlagRequired("file")
	_ = verify.MarkFlagRequired("trusted-old-root")

	var confirmRoot string
	activate := &cobra.Command{Use: "activate", Args: cobra.NoArgs, Short: "Persist and activate a verified transition", RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(artefactFile)
		if err != nil {
			return err
		}
		inspection, err := licencefmt.InspectRootTransition(string(raw))
		if err != nil {
			return err
		}
		if confirmRoot != inspection.Payload.NewRootKeyID {
			return errors.New("--confirm-new-root must exactly match the signed new_root_key_id")
		}
		var value any
		if err = call(cmd.Context(), http.MethodPost, "/admin/v1/root-transitions/activate", map[string]string{"artifact": strings.TrimSpace(string(raw)), "confirm_new_root": confirmRoot}, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	activate.Flags().StringVar(&artefactFile, "file", "", "root transition artefact")
	activate.Flags().StringVar(&confirmRoot, "confirm-new-root", "", "repeat the full signed new root key ID")
	_ = activate.MarkFlagRequired("file")
	_ = activate.MarkFlagRequired("confirm-new-root")

	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List persisted transitions", RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/root-transitions", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	show := &cobra.Command{Use: "show TRANSITION_ID", Args: cobra.ExactArgs(1), Short: "Show a persisted transition", RunE: func(cmd *cobra.Command, args []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/root-transitions/"+url.PathEscape(args[0]), nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}}

	var lifecycleReason, confirmOld, confirmNew string
	var compromiseOld bool
	retire := &cobra.Command{Use: "retire TRANSITION_ID", Args: cobra.ExactArgs(1), Short: "Finish cutover and retire the old root", RunE: func(cmd *cobra.Command, args []string) error {
		var current domain.RootTransition
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/root-transitions/"+url.PathEscape(args[0]), nil, &current); err != nil {
			return err
		}
		if confirmOld != current.OldRootKeyID {
			return errors.New("--confirm-old-root must exactly match old_root_key_id")
		}
		var value any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/root-transitions/"+url.PathEscape(args[0])+"/retire", map[string]any{"reason": lifecycleReason, "compromise_old": compromiseOld, "confirm_old_root": confirmOld}, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	retire.Flags().StringVar(&lifecycleReason, "reason", "", "required lifecycle reason")
	retire.Flags().StringVar(&confirmOld, "confirm-old-root", "", "repeat the full old root key ID")
	retire.Flags().BoolVar(&compromiseOld, "compromised-old", false, "emergency cutover: distrust the old root immediately and stop an old-root issuer")
	_ = retire.MarkFlagRequired("reason")
	_ = retire.MarkFlagRequired("confirm-old-root")

	var compromiseNew bool
	rollback := &cobra.Command{Use: "rollback TRANSITION_ID", Args: cobra.ExactArgs(1), Short: "Rollback during overlap and distrust the new root", RunE: func(cmd *cobra.Command, args []string) error {
		var current domain.RootTransition
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/root-transitions/"+url.PathEscape(args[0]), nil, &current); err != nil {
			return err
		}
		if confirmNew != current.NewRootKeyID {
			return errors.New("--confirm-new-root must exactly match new_root_key_id")
		}
		var value any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/root-transitions/"+url.PathEscape(args[0])+"/rollback", map[string]any{"reason": lifecycleReason, "compromise_new": compromiseNew, "confirm_new_root": confirmNew}, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	rollback.Flags().StringVar(&lifecycleReason, "reason", "", "required rollback reason")
	rollback.Flags().StringVar(&confirmNew, "confirm-new-root", "", "repeat the full new root key ID")
	rollback.Flags().BoolVar(&compromiseNew, "compromised-new", false, "mark the new root compromised and stop a new-root issuer")
	_ = rollback.MarkFlagRequired("reason")
	_ = rollback.MarkFlagRequired("confirm-new-root")

	transition.AddCommand(generate, inspect, verify, activate, list, show, retire, rollback)
	c.AddCommand(transition)
	c.AddCommand(&cobra.Command{Use: "keyring", Args: cobra.NoArgs, Short: "Show the persisted client trust keyring", RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/roots/keyring", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})
	c.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List persisted root metadata", RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/roots", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})
	return c
}

func archiveCmd() *cobra.Command {
	c := &cobra.Command{Use: "archive", Short: "Archive status and reconciliation"}
	var deep, repair bool
	c.AddCommand(&cobra.Command{Use: "status", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/archive/status", nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}})
	reconcile := &cobra.Command{Use: "reconcile", RunE: func(cmd *cobra.Command, _ []string) error {
		if repair && !deep {
			return errors.New("--repair requires --deep")
		}
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/archive/reconcile", map[string]bool{"deep": deep, "repair": repair}, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	reconcile.Flags().BoolVar(&deep, "deep", false, "compare every paid licence, hash and revocation")
	reconcile.Flags().BoolVar(&repair, "repair", false, "queue only safe DB-to-archive repairs")
	c.AddCommand(reconcile, &cobra.Command{Use: "verify", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/archive/verify", struct{}{}, &v); err != nil {
			return err
		}
		return printValue(v)
	}})
	return c
}

func backupCmd() *cobra.Command {
	c := &cobra.Command{Use: "backup", Short: "Create physical and logical backups"}
	var output, backupReason string
	create := &cobra.Command{Use: "create", RunE: func(cmd *cobra.Command, _ []string) error {
		_, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		if output == "" {
			return errors.New("--output is required")
		}
		if err = repo.Backup(cmd.Context(), output); err != nil {
			return err
		}
		if err = appendOperationalAudit(cmd.Context(), repo, "backup.created", "backup", filepath.Base(output), time.Now().UTC(), map[string]any{"result": "success", "reason": backupReason}); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "created", "output": output})
	}}
	create.Flags().StringVarP(&output, "output", "o", "", "output SQLite file")
	create.Flags().StringVar(&backupReason, "reason", "manual", "operational reason recorded in the audit event")
	var destination string
	var compress, includeAudit bool
	export := &cobra.Command{Use: "export", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		if destination == "" {
			return errors.New("--destination is required")
		}
		remote := strings.HasPrefix(strings.ToLower(destination), "s3://")
		if remote && !compress {
			return errors.New("S3 logical exports require --compress")
		}
		staging := destination
		var temporaryRoot string
		if compress {
			temporaryRoot, err = os.MkdirTemp("", "licd-logical-export-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(temporaryRoot)
			staging = filepath.Join(temporaryRoot, "export")
		}
		if err = repo.ExportLogicalWithOptions(cmd.Context(), staging, buildinfo.Version, includeAudit); err != nil {
			return err
		}
		actualDestination := destination
		if compress {
			archiveFile := destination
			if remote {
				archiveFile = filepath.Join(temporaryRoot, "logical-export.tar.gz")
			} else if !strings.HasSuffix(strings.ToLower(archiveFile), ".tar.gz") {
				return errors.New("compressed local destination must end in .tar.gz")
			}
			if err = logicalbackup.Compress(staging, archiveFile); err != nil {
				return err
			}
			if remote {
				store, storeErr := logicalbackup.NewS3(cmd.Context(), cfg)
				if storeErr != nil {
					return storeErr
				}
				actualDestination, err = store.Upload(cmd.Context(), destination, archiveFile)
				if err != nil {
					return err
				}
			}
		}
		if err = appendOperationalAudit(cmd.Context(), repo, "backup.exported", "backup", filepath.Base(destination), time.Now().UTC(), map[string]any{"result": "success"}); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "exported", "destination": actualDestination})
	}}
	export.Flags().StringVar(&destination, "destination", "", "new output directory, .tar.gz file, or s3:// bucket prefix")
	export.Flags().BoolVar(&compress, "compress", false, "create a gzip-compressed tar archive")
	export.Flags().BoolVar(&includeAudit, "include-audit", true, "include the audit-event stream")
	verify := &cobra.Command{Use: "verify FILE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		primary, err := config.Load(opts.config)
		if err != nil {
			return err
		}
		cfg := primary
		cfg.Database.DSN = args[0]
		repo, err := sqliterepo.Open(cfg)
		if err != nil {
			return err
		}
		defer repo.Close()
		if err = repo.Verify(cmd.Context(), true); err != nil {
			return err
		}
		primaryRepo, err := sqliterepo.Open(primary)
		if err != nil {
			return fmt.Errorf("open primary database for audit: %w", err)
		}
		defer primaryRepo.Close()
		absolute, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		digest, size, err := hashFile(absolute)
		if err != nil {
			return err
		}
		verifiedAt := time.Now().UTC()
		verification := domain.BackupVerification{VerificationID: uuid.NewString(), Location: absolute, SHA256: digest, SizeBytes: size, VerifiedAt: verifiedAt}
		audit := operationalAuditEvent("backup.verified", "backup", filepath.Base(absolute), verifiedAt, map[string]any{"result": "success", "sha256": digest, "size_bytes": size})
		if err = primaryRepo.RecordBackupVerification(cmd.Context(), verification, audit); err != nil {
			return err
		}
		return printValue(map[string]any{"status": "ok", "backup": absolute, "sha256": digest, "verified_at": verifiedAt})
	}}
	status := &cobra.Command{Use: "status", Short: "Show continuous replica health", RunE: func(cmd *cobra.Command, _ []string) error {
		var v any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/backup/status", nil, &v); err != nil {
			return err
		}
		return printValue(v)
	}}
	var listDestination string
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List logical backup archives", RunE: func(cmd *cobra.Command, _ []string) error {
		if listDestination == "" {
			return errors.New("--destination is required")
		}
		if strings.HasPrefix(strings.ToLower(listDestination), "s3://") {
			cfg, err := config.Load(opts.config)
			if err != nil {
				return err
			}
			store, err := logicalbackup.NewS3(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			objects, err := store.List(cmd.Context(), listDestination)
			if err != nil {
				return err
			}
			return printValue(map[string]any{"backups": objects})
		}
		entries, err := os.ReadDir(listDestination)
		if err != nil {
			return err
		}
		var paths []string
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(strings.ToLower(entry.Name()), ".tar.gz") {
				paths = append(paths, filepath.Join(listDestination, entry.Name()))
			}
		}
		return printValue(map[string]any{"backups": paths})
	}}
	list.Flags().StringVar(&listDestination, "destination", "", "local directory or s3:// bucket prefix")
	c.AddCommand(create, export, verify, list, status)
	return c
}

func restoreCmd() *cobra.Command {
	c := &cobra.Command{Use: "restore", Short: "Restore a new database from the continuous S3 replica"}
	var output string
	var dryRun bool
	run := func(cmd *cobra.Command, timestamp *time.Time) error {
		cfg, err := config.Load(opts.config)
		if err != nil {
			return err
		}
		return executeRestore(cmd.Context(), cfg, output, timestamp, dryRun)
	}
	latest := &cobra.Command{Use: "latest", Args: cobra.NoArgs, Short: "Restore the latest recoverable database", RunE: func(cmd *cobra.Command, _ []string) error {
		return run(cmd, nil)
	}}
	latest.Flags().StringVarP(&output, "output", "o", "", "new database output path")
	latest.Flags().BoolVar(&dryRun, "dry-run", false, "validate and print the Litestream restore plan without writing")
	_ = latest.MarkFlagRequired("output")
	var pointOutput string
	var pointDryRun bool
	point := &cobra.Command{Use: "point-in-time TIMESTAMP", Args: cobra.ExactArgs(1), Short: "Restore to an RFC3339 recovery point", RunE: func(cmd *cobra.Command, args []string) error {
		timestamp, err := time.Parse(time.RFC3339Nano, args[0])
		if err != nil {
			return fmt.Errorf("timestamp must be RFC3339: %w", err)
		}
		cfg, err := config.Load(opts.config)
		if err != nil {
			return err
		}
		return executeRestore(cmd.Context(), cfg, pointOutput, &timestamp, pointDryRun)
	}}
	point.Flags().StringVarP(&pointOutput, "output", "o", "", "new database output path")
	point.Flags().BoolVar(&pointDryRun, "dry-run", false, "validate and print the Litestream restore plan without writing")
	_ = point.MarkFlagRequired("output")
	points := &cobra.Command{Use: "points", Args: cobra.NoArgs, Short: "List retained LTX restore boundaries", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(opts.config)
		if err != nil {
			return err
		}
		values, err := continuousbackup.RestorePoints(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		return printValue(map[string]any{"restore_points": values})
	}}
	c.AddCommand(latest, point, points)
	return c
}

func recoveryDrillCmd() *cobra.Command {
	c := &cobra.Command{Use: "recovery-drill", Short: "Run and inspect isolated production recovery drills"}
	c.AddCommand(&cobra.Command{Use: "status", Args: cobra.NoArgs, Short: "Show schedule, readiness and alert state", RunE: func(cmd *cobra.Command, _ []string) error {
		var value recoverydrill.Status
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/recovery-drills/status", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})
	var listLimit int
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List persisted drill reports", RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, fmt.Sprintf("/admin/v1/recovery-drills?limit=%d", listLimit), nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	list.Flags().IntVar(&listLimit, "limit", 100, "maximum reports to return (1-1000)")
	c.AddCommand(list)
	c.AddCommand(&cobra.Command{Use: "show DRILL_ID", Args: cobra.ExactArgs(1), Short: "Show one persisted drill report", RunE: func(cmd *cobra.Command, args []string) error {
		var value recoverydrill.Report
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/recovery-drills/"+url.PathEscape(args[0]), nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})

	var mode, licdBinary string
	var wait, exerciseRestart bool
	var waitTimeout time.Duration
	run := &cobra.Command{Use: "run", Args: cobra.NoArgs, Short: "Start a simulation or credentialed recovery drill", RunE: func(cmd *cobra.Command, _ []string) error {
		request := recoverydrill.Request{Mode: mode, Trigger: "manual"}
		if exerciseRestart {
			evidence, err := exerciseServiceRestart(cmd.Context(), licdBinary, waitTimeout)
			if err != nil {
				return err
			}
			request.RestartEvidence = &evidence
		}
		var accepted struct {
			DrillID string `json:"drill_id"`
			Status  string `json:"status"`
		}
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/recovery-drills", request, &accepted); err != nil {
			return err
		}
		if !wait {
			return printValue(accepted)
		}
		deadline := time.Now().Add(waitTimeout)
		for time.Now().Before(deadline) {
			var report recoverydrill.Report
			err := call(cmd.Context(), http.MethodGet, "/admin/v1/recovery-drills/"+url.PathEscape(accepted.DrillID), nil, &report)
			if err == nil {
				if printErr := printValue(report); printErr != nil {
					return printErr
				}
				if report.Status != recoverydrill.StatusPassed {
					return fmt.Errorf("recovery drill completed with status %s", report.Status)
				}
				return nil
			}
			select {
			case <-cmd.Context().Done():
				return cmd.Context().Err()
			case <-time.After(time.Second):
			}
		}
		return fmt.Errorf("timed out waiting for recovery drill %s", accepted.DrillID)
	}}
	run.Flags().StringVar(&mode, "mode", "", "drill mode: simulation or credentialed (default from server configuration)")
	run.Flags().BoolVar(&wait, "wait", false, "wait for and print the final report")
	run.Flags().DurationVar(&waitTimeout, "timeout", 2*time.Hour+5*time.Minute, "maximum time to wait for service restart and drill completion")
	run.Flags().BoolVar(&exerciseRestart, "exercise-service-restart", false, "restart the installed licd OS service and attach boot/readiness evidence")
	run.Flags().StringVar(&licdBinary, "licd-binary", "licd", "licd executable used for the explicit OS service restart")
	c.AddCommand(run)
	return c
}

func exerciseServiceRestart(ctx context.Context, binary string, timeout time.Duration) (recoverydrill.RestartEvidence, error) {
	var before struct {
		BootID string `json:"boot_id"`
	}
	if err := call(ctx, http.MethodGet, "/admin/v1/health/live", nil, &before); err != nil {
		return recoverydrill.RestartEvidence{}, fmt.Errorf("read service boot identity before restart: %w", err)
	}
	if before.BootID == "" {
		return recoverydrill.RestartEvidence{}, errors.New("server did not return a boot identity")
	}
	args := []string{}
	if opts.config != "" {
		args = append(args, "--config", opts.config)
	}
	args = append(args, "service", "restart")
	started := time.Now().UTC()
	restartCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := exec.CommandContext(restartCtx, binary, args...).CombinedOutput()
	if err != nil {
		return recoverydrill.RestartEvidence{}, fmt.Errorf("restart installed licd service: %w: %s", err, strings.TrimSpace(string(output)))
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var after struct {
			BootID string `json:"boot_id"`
		}
		liveErr := call(ctx, http.MethodGet, "/admin/v1/health/live", nil, &after)
		if liveErr == nil && after.BootID != "" && after.BootID != before.BootID {
			var ready any
			if readyErr := call(ctx, http.MethodGet, "/admin/v1/health/ready", nil, &ready); readyErr == nil {
				return recoverydrill.RestartEvidence{BeforeBootID: before.BootID, AfterBootID: after.BootID, RestartedAt: time.Now().UTC(), ReadyAfterSeconds: time.Since(started).Seconds()}, nil
			}
		}
		select {
		case <-ctx.Done():
			return recoverydrill.RestartEvidence{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return recoverydrill.RestartEvidence{}, errors.New("service did not return with a new boot identity and ready state before timeout")
}

func dbCmd() *cobra.Command {
	c := &cobra.Command{Use: "db", Short: "Database maintenance"}
	var deep bool
	verify := &cobra.Command{Use: "verify", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		_ = cfg
		if err = repo.Verify(cmd.Context(), deep); err != nil {
			return err
		}
		if err = appendOperationalAudit(cmd.Context(), repo, "database.verified", "database", filepath.Base(cfg.Database.DSN), time.Now().UTC(), map[string]any{"result": "success", "deep": deep}); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "ok"})
	}}
	verify.Flags().BoolVar(&deep, "deep", false, "run SQLite integrity_check")
	var forceWithoutBackup, migrationPlan bool
	migrate := &cobra.Command{Use: "migrate", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		plan, err := repo.MigrationPlan(cmd.Context())
		if err != nil {
			return err
		}
		if migrationPlan {
			return printValue(map[string]any{"migrations": plan})
		}
		if err = repo.MigrateWithOptions(cmd.Context(), sqliterepo.MigrationOptions{AllowDestructive: true, ForceWithoutBackup: forceWithoutBackup, BackupMaxAge: cfg.Database.MigrationBackupMaxAge}); err != nil {
			return err
		}
		if err = appendOperationalAudit(cmd.Context(), repo, "database.migrated", "database", "primary", time.Now().UTC(), map[string]any{"result": "success", "migrations": plan, "forced_without_backup": forceWithoutBackup}); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "migrated"})
	}}
	migrate.Flags().BoolVar(&forceWithoutBackup, "force-without-backup", false, "permit destructive migration without recent verified backup evidence")
	migrate.Flags().BoolVar(&migrationPlan, "plan", false, "print pending migration classifications without applying them")
	status := &cobra.Command{Use: "status", RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		if err = repo.Ping(cmd.Context()); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "ok", "driver": cfg.Database.Driver, "database": cfg.Database.DSN})
	}}
	var archiveDir, output, rootPublic string
	var rootTransitions []string
	rebuild := &cobra.Command{Use: "rebuild", RunE: func(cmd *cobra.Command, _ []string) error {
		root, err := signing.ReadPublicKey(rootPublic)
		if err != nil {
			return err
		}
		keyring := licencefmt.NewFixedKeyring(root)
		for _, transitionFile := range rootTransitions {
			raw, readErr := os.ReadFile(transitionFile)
			if readErr != nil {
				return fmt.Errorf("read root transition %s: %w", transitionFile, readErr)
			}
			inspection, inspectErr := licencefmt.InspectRootTransition(string(raw))
			if inspectErr != nil {
				return fmt.Errorf("inspect root transition %s: %w", transitionFile, inspectErr)
			}
			keyring, _, inspectErr = keyring.ApplyRootTransition(string(raw), inspection.Payload.NotBefore)
			if inspectErr != nil {
				return fmt.Errorf("apply root transition %s: %w", transitionFile, inspectErr)
			}
		}
		cfg, err := config.Load(opts.config)
		if err != nil {
			return err
		}
		var store domain.ArchiveStore
		if strings.HasPrefix(strings.ToLower(archiveDir), "s3://") {
			store, err = archives3.NewReader(cmd.Context(), cfg, archiveDir)
		} else {
			store, err = archivefs.New(archiveDir)
		}
		if err != nil {
			return err
		}
		report, err := recovery.RebuildFromStoreKeyring(cmd.Context(), store, output, keyring)
		if err != nil {
			return err
		}
		return printValue(map[string]any{"status": "rebuilt", "report": report, "output": output})
	}}
	rebuild.Flags().StringVar(&archiveDir, "from-archive", "", "filesystem archive directory or s3:// URL")
	rebuild.Flags().StringVarP(&output, "output", "o", "", "new SQLite database path")
	rebuild.Flags().StringVar(&rootPublic, "root-public-key", "", "trusted root public key")
	rebuild.Flags().StringSliceVar(&rootTransitions, "root-transition", nil, "ordered persisted root-transition artefact used to verify rotated-root licences")
	_ = rebuild.MarkFlagRequired("from-archive")
	_ = rebuild.MarkFlagRequired("output")
	_ = rebuild.MarkFlagRequired("root-public-key")
	c.AddCommand(status, migrate, verify, rebuild)
	return c
}
func auditCmd() *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Audit-chain operations"}
	c.AddCommand(&cobra.Command{Use: "verify", RunE: func(cmd *cobra.Command, _ []string) error {
		_, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		if err = repo.VerifyAudit(cmd.Context()); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "ok"})
	}})
	var output string
	export := &cobra.Command{Use: "export", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, repo, err := openRepo(cmd.Context())
		if err != nil {
			return err
		}
		defer repo.Close()
		if output == "" {
			return errors.New("--output is required")
		}
		if err = repo.ExportAudit(cmd.Context(), output); err != nil {
			return err
		}
		if err = appendOperationalAudit(cmd.Context(), repo, "audit.exported", "audit", filepath.Base(output), time.Now().UTC(), map[string]any{"result": "success"}); err != nil {
			return err
		}
		return printValue(map[string]string{"status": "exported", "output": output})
	}}
	export.Flags().StringVarP(&output, "output", "o", "", "new audit NDJSON file")
	c.AddCommand(export)
	return c
}

func dataRetentionCmd() *cobra.Command {
	c := &cobra.Command{Use: "retention", Short: "Plan and apply versioned retention policies"}
	policy := &cobra.Command{Use: "policy", Short: "Manage active category policies"}
	policy.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/data-retention/policies", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})
	var category string
	var retainFor time.Duration
	var requireExport bool
	set := &cobra.Command{Use: "set", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if retainFor <= 0 || retainFor%time.Second != 0 {
			return errors.New("--retain-for must be a positive whole-second duration")
		}
		var value any
		request := map[string]any{"category": category, "retain_for_seconds": int64(retainFor / time.Second), "require_export": requireExport}
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/data-retention/policies", request, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	set.Flags().StringVar(&category, "category", "", "expired_trials, revoked_activations, or revoked_licences")
	set.Flags().DurationVar(&retainFor, "retain-for", 0, "minimum age before deletion")
	set.Flags().BoolVar(&requireExport, "require-export", false, "require a matching verified production export")
	_ = set.MarkFlagRequired("category")
	_ = set.MarkFlagRequired("retain-for")
	policy.AddCommand(set)

	var exportSHA string
	var acknowledge bool
	plan := &cobra.Command{Use: "plan", Args: cobra.NoArgs, Short: "Dry-run all active retention policies", RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		request := domain.RetentionApplyRequest{ExportSHA256: exportSHA, AcknowledgeImmutable: acknowledge}
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/data-retention/plan", request, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	plan.Flags().StringVar(&exportSHA, "export-sha256", "", "matching server-verified §80 export SHA-256")
	plan.Flags().BoolVar(&acknowledge, "acknowledge-immutable-residue", false, "acknowledge retained audit/archive/backup copies")

	var applySHA, reason, confirm string
	var applyAcknowledge bool
	apply := &cobra.Command{Use: "apply", Args: cobra.NoArgs, Short: "Transactionally apply all active policies", RunE: func(cmd *cobra.Command, _ []string) error {
		if confirm != "APPLY RETENTION" {
			return errors.New("--confirm must exactly equal APPLY RETENTION")
		}
		var value any
		request := domain.RetentionApplyRequest{Reason: reason, ExportSHA256: applySHA, AcknowledgeImmutable: applyAcknowledge}
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/data-retention/apply", request, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	apply.Flags().StringVar(&reason, "reason", "", "required operational reason")
	apply.Flags().StringVar(&applySHA, "export-sha256", "", "matching server-verified §80 export SHA-256")
	apply.Flags().BoolVar(&applyAcknowledge, "acknowledge-immutable-residue", false, "acknowledge retained audit/archive/backup copies")
	apply.Flags().StringVar(&confirm, "confirm", "", "must exactly equal APPLY RETENTION")
	_ = apply.MarkFlagRequired("reason")
	_ = apply.MarkFlagRequired("confirm")
	c.AddCommand(policy, plan, apply)
	return c
}

func dataDeleteCmd() *cobra.Command {
	var product, licence, customer, reason, exportSHA, confirm string
	var requireExport, acknowledge, apply bool
	command := &cobra.Command{Use: "delete", Args: cobra.NoArgs, Short: "Plan or apply exact-scope production-data deletion", RunE: func(cmd *cobra.Command, _ []string) error {
		scope := domain.DataScope{ProductID: product, LicenceID: licence, CustomerRef: customer}
		request := domain.DataDeletionRequest{Scope: scope, Reason: reason, ExportSHA256: exportSHA, RequireExport: requireExport, AcknowledgeImmutable: acknowledge}
		path := "/admin/v1/data-deletions/plan"
		if apply {
			expected := licence
			if expected == "" {
				expected = customer
			}
			if expected == "" {
				expected = product
			}
			if expected == "" || confirm != expected {
				return errors.New("--confirm must exactly match the licence, customer reference, or product scope")
			}
			path = "/admin/v1/data-deletions"
		}
		var value any
		if err := call(cmd.Context(), http.MethodPost, path, request, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	command.Flags().StringVar(&product, "product", "", "exact product ID scope")
	command.Flags().StringVar(&licence, "licence", "", "exact licence ID scope")
	command.Flags().StringVar(&customer, "customer-ref", "", "exact opaque customer reference scope")
	command.Flags().StringVar(&reason, "reason", "", "required deletion or planning reason")
	command.Flags().StringVar(&exportSHA, "export-sha256", "", "matching server-verified §80 export SHA-256")
	command.Flags().BoolVar(&requireExport, "require-export", false, "block unless the export proof matches the scope")
	command.Flags().BoolVar(&acknowledge, "acknowledge-immutable-residue", false, "acknowledge retained audit/archive/backup copies")
	command.Flags().BoolVar(&apply, "apply", false, "perform the planned deletion; default is dry-run")
	command.Flags().StringVar(&confirm, "confirm", "", "repeat the most specific exact scope when applying")
	_ = command.MarkFlagRequired("reason")
	return command
}

func dataHoldCmd() *cobra.Command {
	c := &cobra.Command{Use: "hold", Short: "Manage deletion-blocking legal holds"}
	var product, licence, customer, reason string
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		request := map[string]any{"scope": domain.DataScope{ProductID: product, LicenceID: licence, CustomerRef: customer}, "reason": reason}
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/data-holds", request, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	create.Flags().StringVar(&product, "product", "", "exact product ID scope")
	create.Flags().StringVar(&licence, "licence", "", "exact licence ID scope")
	create.Flags().StringVar(&customer, "customer-ref", "", "exact opaque customer reference scope")
	create.Flags().StringVar(&reason, "reason", "", "legal or operational hold reason")
	_ = create.MarkFlagRequired("reason")
	var includeReleased bool
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		path := "/admin/v1/data-holds"
		if includeReleased {
			path += "?active=false"
		}
		if err := call(cmd.Context(), http.MethodGet, path, nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	list.Flags().BoolVar(&includeReleased, "include-released", false, "include released holds")
	var releaseReason string
	release := &cobra.Command{Use: "release HOLD_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodPost, "/admin/v1/data-holds/"+url.PathEscape(args[0])+"/release", map[string]string{"reason": releaseReason}, &value); err != nil {
			return err
		}
		return printValue(value)
	}}
	release.Flags().StringVar(&releaseReason, "reason", "", "required release reason")
	_ = release.MarkFlagRequired("reason")
	c.AddCommand(create, list, release)
	return c
}

func dataTombstonesCmd() *cobra.Command {
	c := &cobra.Command{Use: "tombstones", Short: "Inspect privacy-preserving restoration suppressions"}
	c.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		var value any
		if err := call(cmd.Context(), http.MethodGet, "/admin/v1/data-tombstones", nil, &value); err != nil {
			return err
		}
		return printValue(value)
	}})
	return c
}

func dataCmd() *cobra.Command {
	c := &cobra.Command{Use: "data", Short: "Export stable privacy-scoped public data"}
	var output, productID, licenceID, customerRef, status, fromText, toText string
	export := &cobra.Command{Use: "export", Args: cobra.NoArgs, Short: "Download a checksummed public NDJSON bundle", RunE: func(cmd *cobra.Command, _ []string) error {
		if strings.TrimSpace(output) == "" {
			return errors.New("--output is required")
		}
		if !strings.HasSuffix(strings.ToLower(output), ".tar.gz") {
			return errors.New("--output must end in .tar.gz")
		}
		filter := exportdata.Filter{ProductID: productID, LicenceID: licenceID, CustomerRef: customerRef, Status: status}
		var err error
		if fromText != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, fromText)
			if parseErr != nil {
				return fmt.Errorf("--from must be RFC3339: %w", parseErr)
			}
			filter.From = &value
		}
		if toText != "" {
			value, parseErr := time.Parse(time.RFC3339Nano, toText)
			if parseErr != nil {
				return fmt.Errorf("--to must be RFC3339: %w", parseErr)
			}
			filter.To = &value
		}
		if err = dataexporter.ValidateFilter(filter); err != nil {
			return fmt.Errorf("invalid export filters: %w", err)
		}
		absolute, err := filepath.Abs(output)
		if err != nil {
			return err
		}
		if _, err = os.Lstat(absolute); err == nil {
			return fmt.Errorf("refusing to overwrite %s", absolute)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(absolute), 0o750); err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(absolute), ".licd-data-export-*.tmp")
		if err != nil {
			return err
		}
		temporaryPath := temporary.Name()
		committed := false
		defer func() {
			_ = temporary.Close()
			if !committed {
				_ = os.Remove(temporaryPath)
			}
		}()
		client, err := getClient()
		if err != nil {
			return err
		}
		headers, err := client.Download(cmd.Context(), http.MethodPost, "/admin/v1/data-exports", filter, temporary)
		if err != nil {
			return err
		}
		if err = temporary.Sync(); err != nil {
			return err
		}
		if err = temporary.Close(); err != nil {
			return err
		}
		archive, err := os.Open(temporaryPath)
		if err != nil {
			return err
		}
		bundle, inspectErr := dataexporter.ReadArchive(archive)
		closeErr := archive.Close()
		if inspectErr != nil {
			return fmt.Errorf("validate downloaded export: %w", inspectErr)
		}
		if closeErr != nil {
			return closeErr
		}
		sha, size, err := hashFile(temporaryPath)
		if err != nil {
			return err
		}
		serverSHA := strings.TrimSpace(headers.Get("X-Licd-Export-SHA256"))
		if serverSHA == "" || !strings.EqualFold(serverSHA, sha) {
			return errors.New("downloaded export does not match the server SHA-256")
		}
		if err = commitDataExportExclusive(temporaryPath, absolute); err != nil {
			return err
		}
		committed = true
		return printValue(map[string]any{"status": "exported", "output": absolute, "sha256": sha, "size_bytes": size, "schema_version": bundle.Manifest.SchemaVersion, "format_version": bundle.Manifest.FormatVersion, "record_counts": bundle.Manifest.RecordCounts, "filters": bundle.Manifest.Filters})
	}}
	export.Flags().StringVarP(&output, "output", "o", "", "new .tar.gz output file")
	export.Flags().StringVar(&productID, "product", "", "exact product ID")
	export.Flags().StringVar(&licenceID, "licence", "", "exact licence ID")
	export.Flags().StringVar(&customerRef, "customer-ref", "", "exact opaque customer reference")
	export.Flags().StringVar(&status, "status", "", "exact licence status: active or revoked")
	export.Flags().StringVar(&fromText, "from", "", "inclusive RFC3339 occurrence time")
	export.Flags().StringVar(&toText, "to", "", "exclusive RFC3339 occurrence time")
	c.AddCommand(export, dataRetentionCmd(), dataDeleteCmd(), dataHoldCmd(), dataTombstonesCmd())
	return c
}

func commitDataExportExclusive(temporary, destination string) error {
	if err := os.Link(temporary, destination); err == nil {
		// The destination is already complete and durable as the same inode. A
		// failed temporary-name cleanup must not turn a successful exclusive
		// commit into an ambiguous retry that can never overwrite the output.
		_ = os.Remove(temporary)
		return nil
	} else if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("refusing to overwrite %s", destination)
	}
	source, err := os.Open(temporary)
	if err != nil {
		return err
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			_ = source.Close()
		}
	}()
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite %s", destination)
		}
		return err
	}
	ok := false
	defer func() {
		_ = target.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err = io.Copy(target, source); err != nil {
		return err
	}
	if err = source.Close(); err != nil {
		return err
	}
	sourceOpen = false
	if err = target.Sync(); err != nil {
		return err
	}
	if err = target.Close(); err != nil {
		return err
	}
	ok = true
	_ = os.Remove(temporary)
	return nil
}
func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", RunE: func(*cobra.Command, []string) error { return printValue(buildinfo.Current()) }}
}
func openRepo(ctx context.Context) (config.Config, *sqliterepo.Repository, error) {
	cfg, err := config.Load(opts.config)
	if err != nil {
		return cfg, nil, err
	}
	var repo *sqliterepo.Repository
	if cfg.Database.Driver == "postgres" {
		repo, err = postgresrepo.Open(ctx, cfg)
	} else {
		repo, err = sqliterepo.Open(cfg)
	}
	return cfg, repo, err
}

func executeRestore(ctx context.Context, cfg config.Config, output string, timestamp *time.Time, dryRun bool) error {
	started := time.Now().UTC()
	primaryRepo, primaryErr := sqliterepo.Open(cfg)
	if primaryErr == nil {
		_ = appendOperationalAudit(ctx, primaryRepo, "restore.started", "database", filepath.Base(output), started, map[string]any{"result": "started", "dry_run": dryRun, "point_in_time": timestamp})
		_ = primaryRepo.Close()
	}
	result, err := continuousbackup.Restore(ctx, cfg, output, timestamp, dryRun)
	if err != nil {
		if primaryErr == nil {
			if repo, openErr := sqliterepo.Open(cfg); openErr == nil {
				_ = appendOperationalAudit(ctx, repo, "restore.failed", "database", filepath.Base(output), time.Now().UTC(), map[string]any{"result": "failure", "reason_code": "restore_command_failed"})
				_ = repo.Close()
			}
		}
		return err
	}
	auditCfg := cfg
	if !dryRun {
		auditCfg.Database.DSN = output
	}
	repo, openErr := sqliterepo.Open(auditCfg)
	if openErr != nil {
		return fmt.Errorf("open restore audit database: %w", openErr)
	}
	defer repo.Close()
	var suppressionCounts domain.DeletionCounts
	if !dryRun {
		store, storeErr := configuredArchiveStore(ctx, cfg)
		if storeErr == nil {
			suppressionCounts, storeErr = recovery.ApplyArchiveSuppressions(ctx, repo, store, "restore-cli", time.Now().UTC())
		}
		if storeErr != nil {
			_ = repo.Close()
			_ = os.Remove(result.Output)
			if primary, auditErr := sqliterepo.Open(cfg); auditErr == nil {
				_ = appendOperationalAudit(ctx, primary, "restore.failed", "database", filepath.Base(output), time.Now().UTC(), map[string]any{"result": "failure", "reason_code": "suppression_reconciliation_failed"})
				_ = primary.Close()
			}
			return fmt.Errorf("restore suppression reconciliation failed; restored output removed: %w", storeErr)
		}
	}
	if primaryErr != nil {
		if err = appendOperationalAudit(ctx, repo, "restore.started", "database", filepath.Base(output), started, map[string]any{"result": "started", "dry_run": dryRun, "point_in_time": timestamp}); err != nil {
			return err
		}
	}
	if err = appendOperationalAudit(ctx, repo, "restore.completed", "database", filepath.Base(output), time.Now().UTC(), map[string]any{"result": "success", "dry_run": dryRun, "point_in_time": timestamp, "suppression_counts": suppressionCounts}); err != nil {
		return err
	}
	return printValue(result)
}

func configuredArchiveStore(ctx context.Context, cfg config.Config) (domain.ArchiveStore, error) {
	switch cfg.Archive.Provider {
	case "filesystem":
		if info, err := os.Stat(cfg.Archive.Directory); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("configured archive directory is unavailable")
		}
		return archivefs.New(cfg.Archive.Directory)
	case "s3":
		return archives3.New(ctx, cfg)
	default:
		return nil, errors.New("a configured immutable archive is required to suppress deleted data during restore")
	}
}

func appendOperationalAudit(ctx context.Context, repo domain.Repository, eventType, aggregateType, aggregateID string, occurredAt time.Time, details any) error {
	return repo.AppendAudit(ctx, operationalAuditEvent(eventType, aggregateType, aggregateID, occurredAt, details))
}

func operationalAuditEvent(eventType, aggregateType, aggregateID string, occurredAt time.Time, details any) domain.AuditEvent {
	payload, err := json.Marshal(details)
	if err != nil {
		payload = json.RawMessage(`{"result":"failure","reason_code":"audit_serialization"}`)
	}
	actor := strings.TrimSpace(os.Getenv("USERNAME"))
	if actor == "" {
		actor = strings.TrimSpace(os.Getenv("USER"))
	}
	if actor == "" {
		actor = "local-os"
	}
	return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: occurredAt, ActorType: "administrator", ActorRef: "local-cli:" + actor, EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, Event: payload}
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func ensureAbsent(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			return errors.New("output path is empty")
		}
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("refusing to overwrite %s", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	ok = true
	return f.Close()
}
func fingerprint(key ed25519.PublicKey) string {
	sum := ed25519Fingerprint(key)
	return strings.ToUpper(fmt.Sprintf("%x", sum[:8]))
}
func ed25519Fingerprint(key ed25519.PublicKey) [32]byte { return sha256Sum(key) }
