package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/coal/lobstertrap/internal/audit"
	"github.com/coal/lobstertrap/internal/pipeline"
	"github.com/coal/lobstertrap/internal/policy"
)

var inspectPolicyFile string

var inspectCmd = &cobra.Command{
	Use:   "inspect [prompt text]",
	Short: "Inspect a single prompt and show extracted metadata",
	Long:  "Run deep prompt inspection on the given text and display the extracted metadata, risk score, and policy decision.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runInspect,
}

func init() {
	inspectCmd.Flags().StringVar(&inspectPolicyFile, "policy", "configs/default_policy.yaml", "Path to policy YAML file")
}

func runInspect(cmd *cobra.Command, args []string) error {
	promptText := strings.Join(args, " ")

	// Load policy
	pol, err := policy.LoadFromFile(inspectPolicyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	// Create pipeline with no-op audit logger
	pipe := pipeline.New(pol, audit.NopLogger())

	// Run inspection
	meta := pipe.InspectOnly(promptText)

	// Run ingress evaluation
	result := pipe.ProcessIngress(promptText, nil)

	// Output metadata
	fmt.Fprintf(os.Stderr, "\n=== Deep Prompt Inspection ===\n\n")
	fmt.Fprintf(os.Stderr, "Prompt: %q\n\n", truncate(promptText, 120))

	// Pretty print metadata
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	fmt.Fprintf(os.Stdout, "%s\n", metaJSON)

	// Print decision
	fmt.Fprintf(os.Stderr, "\n=== Policy Decision ===\n\n")
	fmt.Fprintf(os.Stderr, "  Action:  %s\n", result.IngressResult.Action)
	if result.IngressResult.RuleName != "" {
		fmt.Fprintf(os.Stderr, "  Rule:    %s\n", result.IngressResult.RuleName)
	}
	if result.DenyMessage != "" {
		fmt.Fprintf(os.Stderr, "  Message: %s\n", result.DenyMessage)
	}
	fmt.Fprintln(os.Stderr)

	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
