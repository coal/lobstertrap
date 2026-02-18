package cmd

import "github.com/spf13/cobra"

// Version is set at build time.
var Version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "lobstertrap",
	Short: "Lobster Trap — Deep Prompt Inspection for LLM Inference",
	Long: `Lobster Trap is a security middleware for AI agents.
It sits between an AI agent and the LLM, inspecting every prompt and
every output using deep prompt inspection — regex-based metadata extraction
evaluated against programmable firewall rules.`,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("lobstertrap v%s\n", Version)
	},
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
