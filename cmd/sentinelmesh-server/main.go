package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fully-ai/sentinelmesh/internal/api"
	scrypto "github.com/fully-ai/sentinelmesh/internal/crypto"
	"github.com/fully-ai/sentinelmesh/internal/detection"
	"github.com/fully-ai/sentinelmesh/internal/domain"
	"github.com/fully-ai/sentinelmesh/internal/pipeline"
	"github.com/fully-ai/sentinelmesh/internal/plugin"
	"github.com/fully-ai/sentinelmesh/internal/storage"
	"github.com/fully-ai/sentinelmesh/internal/threatintel"
	"github.com/google/uuid"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8440", "HTTP/HTTPS listen address")
	dbPath := flag.String("db", "data/sentinelmesh.db", "SQLite database path")
	tlsCert := flag.String("tls-cert", "", "Path to TLS server certificate PEM")
	tlsKey := flag.String("tls-key", "", "Path to TLS server private key PEM")
	tlsClientCA := flag.String("tls-client-ca", "", "Optional client CA PEM to enforce mTLS")
	allowDisruptive := flag.Bool("allow-disruptive", os.Getenv("SENTINELMESH_ALLOW_DISRUPTIVE") == "true", "Allow disruptive endpoint containment actions")
	queueCap := flag.Int("queue-cap", 4096, "Bounded event ingestion queue capacity")
	retentionHours := flag.Int("retention-hours", 24*30, "Maximum event age in hours")
	retentionMaxRows := flag.Int("retention-max-rows", 250000, "Maximum retained events")
	pluginScript := flag.String("enricher-plugin", "", "Optional path to sandboxed alert plugin binary")
	flag.Parse()

	if dir := filepath.Dir(*dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			log.Fatalf("create data directory: %v", err)
		}
	}

	store, err := storage.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	jwtSecret := os.Getenv("SENTINELMESH_JWT_SECRET")
	if len(jwtSecret) < 16 {
		jwtSecret, err = scrypto.GenerateRandomHex(32)
		if err != nil {
			log.Fatalf("generate jwt secret: %v", err)
		}
		log.Println("[INFO] Generated ephemeral JWT signing key (set SENTINELMESH_JWT_SECRET in production)")
	}

	// Bootstrap initial admin user if empty
	if users, err := store.ListUsers(ctx, "*"); err == nil && len(users) == 0 {
		pass := os.Getenv("SENTINELMESH_ADMIN_PASSWORD")
		generated := false
		if pass == "" {
			pass, err = scrypto.GenerateRandomHex(12)
			if err != nil {
				log.Fatalf("generate admin password: %v", err)
			}
			generated = true
		}
		hash, err := scrypto.HashPassword(pass)
		if err != nil {
			log.Fatalf("hash bootstrap admin password: %v", err)
		}
		admin := &domain.User{
			ID:           uuid.NewString(),
			TenantID:     "default",
			Username:     "admin",
			Email:        "soc-admin@localhost",
			Role:         domain.RoleAdmin,
			PasswordHash: hash,
		}
		if err := store.CreateUser(ctx, admin); err != nil {
			log.Fatalf("create bootstrap admin: %v", err)
		}
		if generated {
			log.Printf("[BOOTSTRAP] Created initial admin user 'admin' with generated one-time password: %s", pass)
		} else {
			log.Println("[BOOTSTRAP] Created initial admin user 'admin' from SENTINELMESH_ADMIN_PASSWORD")
		}
	}

	rules, err := detection.SeedDefaultRules(ctx, store)
	if err != nil {
		log.Fatalf("seed detection rules: %v", err)
	}
	engine := detection.NewEngine(rules)

	activeIOCs, _ := store.ListActiveIOCs(ctx, "*", time.Now().UTC())
	iocMatcher := threatintel.NewMatcher(activeIOCs, time.Now().UTC())

	var plugins []plugin.PluginSpec
	if *pluginScript != "" {
		plugins = append(plugins, plugin.PluginSpec{
			ID: "custom-enricher", Name: "Custom Alert Enricher", Kind: "enricher", Binary: *pluginScript, Enabled: true,
		})
	}
	pluginRunner := plugin.NewRunner(plugins, 3*time.Second)

	pipe := pipeline.New(store, engine, iocMatcher, *queueCap)
	pipe.Start(4)
	defer pipe.Stop()

	srvHandler := api.NewServer(store, pipe, engine, iocMatcher, pluginRunner, api.ServerConfig{
		JWTSecret:       []byte(jwtSecret),
		AllowDisruptive: *allowDisruptive,
		RetentionMaxAge: time.Duration(*retentionHours) * time.Hour,
		RetentionMaxRow: *retentionMaxRows,
		WebFS:           api.WebAssets,
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srvHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	if *tlsCert != "" && *tlsKey != "" {
		tlsCfg, err := scrypto.BuildServerTLSConfig(*tlsCert, *tlsKey, *tlsClientCA)
		if err != nil {
			log.Fatalf("tls config: %v", err)
		}
		httpSrv.TLSConfig = tlsCfg
	}

	// Periodic retention cleanup
	stopRetention := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_, _ = store.EnforceRetention(context.Background(), time.Duration(*retentionHours)*time.Hour, *retentionMaxRows)
			case <-stopRetention:
				return
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[SENTINELMESH] Server listening on %s (rules=%d, iocs=%d, disruptive=%v)",
			*addr, len(rules), len(activeIOCs), *allowDisruptive)
		if httpSrv.TLSConfig != nil {
			errCh <- httpSrv.ListenAndServeTLS("", "")
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("[SENTINELMESH] Caught signal %s, shutting down gracefully...", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}
	close(stopRetention)
	shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shCtx)
}
