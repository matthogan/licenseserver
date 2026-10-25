package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kardianos/service"
	"github.com/matthogan/licenceserver/internal/buildinfo"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	"github.com/matthogan/licenceserver/internal/daemon"
	managedlayout "github.com/matthogan/licenceserver/internal/layout"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
	"github.com/spf13/cobra"
)

var configPath string

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "licd", Short: "Offline-first desktop licensing server", SilenceUsage: true}
	root.PersistentFlags().StringVar(&configPath, "config", "", "configuration file")
	root.AddCommand(serveCmd(), versionCmd(), configCmd(), layoutCmd(), serviceCmd())
	return root
}
func serveCmd() *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "Run the public and administrative servers", RunE: func(cmd *cobra.Command, args []string) error {
		c, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if err = c.Validate(true); err != nil {
			return err
		}
		if err = managedlayout.Check(configPath, c); err != nil {
			return fmt.Errorf("filesystem layout: %w; run `licd layout init` with administrative privileges", err)
		}
		p := &serviceProgram{config: c}
		svc, err := service.New(p, serviceConfig(configPath))
		if err != nil {
			return err
		}
		if !service.Interactive() {
			return svc.Run()
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return daemon.Run(ctx, c)
	}}
}
func versionCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{Use: "version", Short: "Print build version", RunE: func(*cobra.Command, []string) error {
		v := buildinfo.Current()
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(v)
		}
		fmt.Printf("licd %s (%s, %s)\n", v.Version, v.Commit, v.Date)
		return nil
	}}
	c.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return c
}
func configCmd() *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Configuration operations"}
	c.AddCommand(&cobra.Command{Use: "check", Short: "Validate configuration and signer files", RunE: func(*cobra.Command, []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if err = cfg.Validate(true); err != nil {
			return err
		}
		if err = managedlayout.Check(configPath, cfg); err != nil {
			return fmt.Errorf("filesystem layout: %w", err)
		}
		if cfg.Backup.Continuous.Enabled {
			if err = continuousbackup.CheckConfiguration(context.Background(), cfg); err != nil {
				return err
			}
		}
		root, err := signing.ReadPublicKey(cfg.Signer.RootPublicKeyFile)
		if err != nil {
			return fmt.Errorf("trusted root public key: %w", err)
		}
		var certificate string
		if cfg.Signer.Provider == "aws-kms" {
			contents, readErr := os.ReadFile(cfg.Signer.IssuerCertificateFile)
			if readErr != nil {
				return fmt.Errorf("issuer certificate: %w", readErr)
			}
			certificate = strings.TrimSpace(string(contents))
		} else {
			local, loadErr := signing.Load(cfg.Signer.PrivateKeyFile, cfg.Signer.IssuerCertificateFile)
			if loadErr != nil {
				return loadErr
			}
			certificate = local.Certificate()
		}
		if _, err = licencefmt.VerifyIssuerCertificate(root, strings.TrimSpace(certificate)); err != nil {
			return fmt.Errorf("issuer certificate is not signed by configured root: %w", err)
		}
		fmt.Println("configuration is valid")
		return nil
	}})
	return c
}

func layoutCmd() *cobra.Command {
	c := &cobra.Command{Use: "layout", Short: "Create and validate managed filesystem locations"}
	c.AddCommand(&cobra.Command{Use: "init", Args: cobra.NoArgs, Short: "Create directories and apply platform security", RunE: func(*cobra.Command, []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if err = managedlayout.Ensure(configPath, cfg); err != nil {
			return err
		}
		fmt.Println("filesystem layout initialized")
		return nil
	}})
	c.AddCommand(&cobra.Command{Use: "check", Args: cobra.NoArgs, Short: "Validate directories and platform security", RunE: func(*cobra.Command, []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if err = managedlayout.Check(configPath, cfg); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ok", "directories": managedlayout.Directories(configPath, cfg)})
	}})
	return c
}

type serviceProgram struct {
	config config.Config
	cancel context.CancelFunc
	done   chan error
}

func (p *serviceProgram) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() { p.done <- daemon.Run(ctx, p.config) }()
	return nil
}
func (p *serviceProgram) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		return <-p.done
	}
	return nil
}
func serviceConfig(path string) *service.Config {
	args := []string{"serve"}
	if path != "" {
		args = append(args, "--config", path)
	}
	return &service.Config{Name: "licd", DisplayName: "Desktop Licensing Server", Description: "Issues and manages offline-verifiable desktop software licences.", Arguments: args}
}
func serviceCmd() *cobra.Command {
	c := &cobra.Command{Use: "service", Short: "Manage the Windows or Linux system service"}
	for _, action := range []string{"install", "uninstall", "start", "stop", "restart", "status"} {
		action := action
		c.AddCommand(&cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
			if action == "install" && (configPath == "" || !filepath.IsAbs(configPath)) {
				return errors.New("service install requires --config with an absolute path")
			}
			cfg, err := config.Load(configPath)
			if err != nil && action == "install" {
				return err
			}
			if action == "install" {
				if err = managedlayout.Ensure(configPath, cfg); err != nil {
					return err
				}
				if err = cfg.Validate(true); err != nil {
					return err
				}
			}
			svc, err := service.New(&serviceProgram{config: cfg}, serviceConfig(configPath))
			if err != nil {
				return err
			}
			switch action {
			case "install":
				err = svc.Install()
			case "uninstall":
				err = svc.Uninstall()
			case "start":
				err = svc.Start()
			case "stop":
				err = svc.Stop()
			case "restart":
				err = service.Control(svc, "restart")
			case "status":
				var status service.Status
				status, err = svc.Status()
				if err == nil {
					fmt.Println(serviceStatus(status))
				}
			}
			if err == nil && action != "status" {
				fmt.Printf("service %s complete\n", action)
			}
			return err
		}})
	}
	return c
}
func serviceStatus(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}
