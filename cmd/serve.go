package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/dashboard"
	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
	"github.com/coal/lobstertrap/internal/proxy"
)

var (
	policyFile  string
	listenAddr  string
	backendURL  string
	auditFile   string
	noDashboard bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Agent Guard reverse proxy",
	Long:  "Start the HTTP reverse proxy that inspects prompts and responses using deep prompt inspection.",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().StringVar(&policyFile, "policy", "configs/default_policy.yaml", "Path to policy YAML file")
	serveCmd.Flags().StringVar(&listenAddr, "listen", ":8080", "Address to listen on")
	serveCmd.Flags().StringVar(&backendURL, "backend", "http://localhost:11434", "Backend LLM server URL")
	serveCmd.Flags().StringVar(&auditFile, "audit-log", "", "Path to audit log file (default: stderr)")
	serveCmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "Disable the real-time dashboard")
}

func runServe(cmd *cobra.Command, args []string) error {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Str("component", "agentguard").Logger()

	// Load policy
	pol, err := policy.LoadFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	logger.Info().
		Str("policy", pol.PolicyName).
		Str("version", pol.Version).
		Int("ingress_rules", len(pol.IngressRules)).
		Int("egress_rules", len(pol.EgressRules)).
		Msg("policy loaded")

	// Set up audit logger
	var auditLogger *audit.Logger
	if auditFile != "" {
		auditLogger, err = audit.NewFileLogger(auditFile)
		if err != nil {
			return fmt.Errorf("creating audit logger: %w", err)
		}
		logger.Info().Str("path", auditFile).Msg("audit log enabled")
	} else {
		auditLogger = audit.NewStderrLogger()
	}

	// Create pipeline
	pipe := pipeline.New(pol, auditLogger)

	// Create proxy
	guardProxy, err := proxy.New(pipe, backendURL, logger)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Set up the HTTP handler — either with dashboard mux or proxy-only
	var handler http.Handler = guardProxy

	if !noDashboard {
		hub := dashboard.NewHub(pol)
		pipe.AddObserver(hub.OnEvent)
		dashboard.Run(context.Background(), hub)

		dashHandler := dashboard.Handler(hub)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/_guard") {
				dashHandler.ServeHTTP(w, r)
				return
			}
			guardProxy.ServeHTTP(w, r)
		})
	}

	logger.Info().
		Str("listen", listenAddr).
		Str("backend", backendURL).
		Msg("starting agent guard proxy")

	fmt.Fprintf(os.Stderr, "\n  Agent Guard v%s\n", Version)
	fmt.Fprintf(os.Stderr, "  Policy:  %s (%s)\n", pol.PolicyName, pol.Version)
	fmt.Fprintf(os.Stderr, "  Listen:  %s\n", listenAddr)
	fmt.Fprintf(os.Stderr, "  Backend: %s\n", backendURL)
	if !noDashboard {
		dashAddr := listenAddr
		if strings.HasPrefix(dashAddr, ":") {
			dashAddr = "localhost" + dashAddr
		}
		fmt.Fprintf(os.Stderr, "  Dashboard: http://%s/_guard/\n", dashAddr)
	}
	fmt.Fprintln(os.Stderr)

	return http.ListenAndServe(listenAddr, handler)
}
