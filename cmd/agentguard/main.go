package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"agentguard/audit"
	"agentguard/config"
	"agentguard/guard"
	"agentguard/model"
	"agentguard/policy"
	"agentguard/report"
	"agentguard/strictjson"
)

const rootUsage = `Usage: agentguard <command> [flags]

Commands:
  validate       Validate a strict JSON policy
  evaluate       Classify and evaluate a strict JSON request
  explain        Evaluate a request with human-readable output
  verify-audit   Verify a tamper-evident audit ledger
  replay         Deterministically replay audited decisions
  sample-policy  Emit a complete example policy as JSON
  sample-config  Emit a complete runtime configuration as JSON
  report         Build a decision report in json, text, or html format

Exit codes: 0 success, 1 invalid input or runtime failure, 2 usage error.
Use "agentguard <command> -h" for command flags.
`

type usageError struct {
	usage string
	err   error
}

func (e usageError) Error() string { return e.err.Error() }

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, rootUsage)
		return 0
	}
	var err error
	switch args[0] {
	case "validate":
		err = runValidate(args[1:], stdin, stdout)
	case "evaluate":
		err = runEvaluate(args[1:], stdin, stdout, false)
	case "explain":
		err = runEvaluate(args[1:], stdin, stdout, true)
	case "verify-audit":
		err = runVerifyAudit(args[1:], stdout)
	case "replay":
		err = runReplay(args[1:], stdin, stdout)
	case "sample-policy":
		err = runSamplePolicy(args[1:], stdout)
	case "sample-config":
		err = runSampleConfig(args[1:], stdout)
	case "report":
		err = runReport(args[1:], stdin, stdout)
	default:
		err = usageError{rootUsage, fmt.Errorf("unknown command %q", args[0])}
	}
	if err == nil {
		return 0
	}
	var u usageError
	if errors.As(err, &u) {
		fmt.Fprintf(stderr, "error: %v\n\n%s", u.err, u.usage)
		return 2
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func commandFlags(name, usage string, args []string, stdout io.Writer) (*flag.FlagSet, error) {
	if hasHelp(args) {
		fmt.Fprint(stdout, usage)
		return nil, flag.ErrHelp
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return flags, nil
}

func hasHelp(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func parseFlags(flags *flag.FlagSet, args []string, usage string) error {
	if err := flags.Parse(args); err != nil {
		return usageError{usage, err}
	}
	if flags.NArg() != 0 {
		return usageError{usage, fmt.Errorf("unexpected argument %q", flags.Arg(0))}
	}
	return nil
}

const validateUsage = `Usage: agentguard validate -policy FILE

Flags:
  -policy FILE  Strict JSON policy file; use - for stdin
`

func runValidate(args []string, stdin io.Reader, stdout io.Writer) error {
	flags, err := commandFlags("validate", validateUsage, args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	policyPath := flags.String("policy", "", "policy file")
	if err := parseFlags(flags, args, validateUsage); err != nil {
		return err
	}
	if *policyPath == "" {
		return usageError{validateUsage, errors.New("-policy is required")}
	}
	p, err := loadPolicy(*policyPath, stdin)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "policy %s@%s is valid\n", p.ID, p.Version)
	return err
}

func loadPolicy(path string, stdin io.Reader) (policy.Policy, error) {
	if path == "-" {
		p, err := policy.Decode(stdin)
		if err != nil {
			return policy.Policy{}, fmt.Errorf("policy: %w", err)
		}
		return p, nil
	}
	p, err := policy.Load(path)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

const evaluateUsage = `Usage: agentguard evaluate -policy FILE [-request FILE] [-config FILE] [-findings FILE] [-audit FILE]

Flags:
  -policy FILE    Strict JSON policy file (required)
  -request FILE   Strict JSON EvaluationRequest; default - (stdin)
  -config FILE    Optional strict AgentGuard runtime configuration
  -findings FILE  Optional strict {"findings":[...]} JSON file
  -audit FILE     Optional tamper-evident JSONL ledger
`

const explainUsage = `Usage: agentguard explain -policy FILE [-request FILE] [-config FILE] [-findings FILE] [-audit FILE]

Flags:
  -policy FILE    Strict JSON policy file (required)
  -request FILE   Strict JSON EvaluationRequest; default - (stdin)
  -config FILE    Optional strict AgentGuard runtime configuration
  -findings FILE  Optional strict {"findings":[...]} JSON file
  -audit FILE     Optional tamper-evident JSONL ledger
`

type findingsInput struct {
	Findings []model.Finding `json:"findings"`
}

func runEvaluate(args []string, stdin io.Reader, stdout io.Writer, explain bool) error {
	usage := evaluateUsage
	name := "evaluate"
	if explain {
		usage, name = explainUsage, "explain"
	}
	flags, err := commandFlags(name, usage, args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	policyPath := flags.String("policy", "", "policy file")
	requestPath := flags.String("request", "-", "request file")
	configPath := flags.String("config", "", "runtime config file")
	findingsPath := flags.String("findings", "", "findings file")
	auditPath := flags.String("audit", "", "audit ledger")
	if err := parseFlags(flags, args, usage); err != nil {
		return err
	}
	if *policyPath == "" {
		return usageError{usage, errors.New("-policy is required")}
	}
	if *policyPath == "-" && *requestPath == "-" {
		return usageError{usage, errors.New("-policy and -request cannot both use stdin")}
	}
	p, err := loadPolicy(*policyPath, stdin)
	if err != nil {
		return err
	}
	var request model.EvaluationRequest
	if err := decodePath(*requestPath, stdin, &request); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	var findings []model.Finding
	if *findingsPath != "" {
		var input findingsInput
		if err := decodePath(*findingsPath, stdin, &input); err != nil {
			return fmt.Errorf("findings: %w", err)
		}
		if input.Findings == nil {
			return errors.New("findings: findings is required")
		}
		findings = input.Findings
	}
	engine, err := guard.New(p)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	if *configPath != "" {
		runtimeConfig, err := config.Load(*configPath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		classifier, err := runtimeConfig.Classifier()
		if err != nil {
			return fmt.Errorf("config classifier: %w", err)
		}
		engine = engine.WithClassifier(classifier)
	}
	if *auditPath != "" {
		ledger, err := audit.New(*auditPath)
		if err != nil {
			return fmt.Errorf("open audit ledger: %w", err)
		}
		defer ledger.Close()
		engine = engine.WithLedger(ledger)
	}
	result, err := engine.EvaluateWithFindings(context.Background(), request, findings)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	if explain {
		return writeExplanation(stdout, result)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write result JSON: %w", err)
	}
	return nil
}

func decodePath(path string, stdin io.Reader, dst any) error {
	if path == "-" {
		if err := strictjson.Decode(stdin, dst); err != nil {
			return err
		}
		return nil
	}
	if err := strictjson.DecodeFile(path, dst); err != nil {
		return err
	}
	return nil
}

func writeExplanation(w io.Writer, result model.DecisionResult) error {
	matched := "none"
	if len(result.MatchedRules) > 0 {
		matched = strings.Join(result.MatchedRules, ", ")
	}
	if _, err := fmt.Fprintf(w, "Decision: %s\nRequest: %s\nPolicy: %s@%s\nRisk: %s\nMatched rules: %s\nFindings: %d\nReasons:\n", result.Decision, result.RequestID, result.PolicyID, result.PolicyVersion, result.Risk, matched, len(result.Findings)); err != nil {
		return fmt.Errorf("write explanation: %w", err)
	}
	for _, reason := range result.Reasons {
		if _, err := fmt.Fprintf(w, "- %s\n", reason); err != nil {
			return fmt.Errorf("write explanation: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "Fingerprint: %s\n", result.Fingerprint); err != nil {
		return fmt.Errorf("write explanation: %w", err)
	}
	return nil
}

const samplePolicyUsage = `Usage: agentguard sample-policy

Emits a complete, valid example policy to stdout.
`

func runSamplePolicy(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, samplePolicyUsage)
		return nil
	}
	if len(args) != 0 {
		return usageError{samplePolicyUsage, fmt.Errorf("unexpected argument %q", args[0])}
	}
	tool := "shell"
	sample := policy.Policy{
		ID: "example-agent-policy", Version: "1.0.0",
		Description:   "Require approval for shell execution and deny high-risk findings.",
		DefaultEffect: policy.EffectAllow,
		Rules: []policy.Rule{
			{
				ID: "deny-high-risk", Priority: 100, Effect: policy.EffectDeny,
				Reason:    "high-risk findings are denied",
				Condition: policy.Condition{Risk: &policy.RiskCondition{Minimum: model.RiskHigh}},
			},
			{
				ID: "approve-shell", Priority: 50, Effect: policy.EffectRequireApproval,
				Reason:    "shell execution requires approval",
				Condition: policy.Condition{Tool: &policy.StringCondition{Equals: &tool}},
			},
		},
	}
	if err := sample.Validate(); err != nil {
		return fmt.Errorf("internal sample policy: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sample); err != nil {
		return fmt.Errorf("write sample policy: %w", err)
	}
	return nil
}

const reportUsage = `Usage: agentguard report [-input FILE] [-format FORMAT] [-output FILE]

Flags:
  -input FILE    Strict {"results":[...]} report.Input; default - (stdin)
  -format VALUE  Output format: json, text, or html; default text
  -output FILE   Output file; default - (stdout)
`

func runReport(args []string, stdin io.Reader, stdout io.Writer) error {
	flags, err := commandFlags("report", reportUsage, args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	inputPath := flags.String("input", "-", "input file")
	format := flags.String("format", "text", "output format")
	outputPath := flags.String("output", "-", "output file")
	if err := parseFlags(flags, args, reportUsage); err != nil {
		return err
	}
	if *format != "json" && *format != "text" && *format != "html" {
		return usageError{reportUsage, fmt.Errorf("invalid -format %q", *format)}
	}
	results, err := decodeReportInput(*inputPath, stdin)
	if err != nil {
		return err
	}
	out, closeOutput, err := outputWriter(*outputPath, stdout)
	if err != nil {
		return err
	}
	defer closeOutput()
	summary := report.Build(results)
	switch *format {
	case "json":
		err = report.WriteJSON(out, summary)
	case "text":
		err = report.WriteText(out, summary)
	case "html":
		err = report.WriteHTML(out, summary)
	}
	if err != nil {
		return fmt.Errorf("render %s report: %w", *format, err)
	}
	return nil
}

func decodeReportInput(path string, stdin io.Reader) ([]model.DecisionResult, error) {
	if path == "-" {
		results, err := report.DecodeResults(stdin)
		if err != nil {
			return nil, fmt.Errorf("report: %w", err)
		}
		return results, nil
	}
	results, err := report.DecodeResultsFile(path)
	if err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	return results, nil
}

func outputWriter(path string, stdout io.Writer) (io.Writer, func(), error) {
	if path == "-" {
		return stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output %s: %w", path, err)
	}
	return file, func() { _ = file.Close() }, nil
}

const verifyAuditUsage = `Usage: agentguard verify-audit -audit FILE

Flags:
  -audit FILE  Tamper-evident JSONL ledger to verify (required)
`

func runVerifyAudit(args []string, stdout io.Writer) error {
	flags, err := commandFlags("verify-audit", verifyAuditUsage, args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	auditPath := flags.String("audit", "", "audit ledger")
	if err := parseFlags(flags, args, verifyAuditUsage); err != nil {
		return err
	}
	if *auditPath == "" {
		return usageError{verifyAuditUsage, errors.New("-audit is required")}
	}
	ledger, err := audit.New(*auditPath)
	if err != nil {
		return fmt.Errorf("open audit ledger: %w", err)
	}
	defer ledger.Close()
	verified, err := ledger.Verify(context.Background())
	if err != nil {
		return fmt.Errorf("verify audit ledger: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(verified); err != nil {
		return fmt.Errorf("write audit verification: %w", err)
	}
	return nil
}

const replayUsage = `Usage: agentguard replay -policy FILE -audit FILE [-config FILE]

Flags:
  -policy FILE  Strict JSON policy used for reevaluation (required)
  -audit FILE   Verified decision ledger to replay (required)
  -config FILE  Original strict runtime configuration, if used
`

func runReplay(args []string, stdin io.Reader, stdout io.Writer) error {
	flags, err := commandFlags("replay", replayUsage, args, stdout)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	policyPath := flags.String("policy", "", "policy file")
	auditPath := flags.String("audit", "", "audit ledger")
	configPath := flags.String("config", "", "runtime config file")
	if err := parseFlags(flags, args, replayUsage); err != nil {
		return err
	}
	if *policyPath == "" || *auditPath == "" {
		return usageError{replayUsage, errors.New("-policy and -audit are required")}
	}
	p, err := loadPolicy(*policyPath, stdin)
	if err != nil {
		return err
	}
	engine, err := guard.New(p)
	if err != nil {
		return fmt.Errorf("create replay engine: %w", err)
	}
	if *configPath != "" {
		runtimeConfig, err := config.Load(*configPath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		classifier, err := runtimeConfig.Classifier()
		if err != nil {
			return fmt.Errorf("config classifier: %w", err)
		}
		engine = engine.WithClassifier(classifier)
	}
	ledger, err := audit.New(*auditPath)
	if err != nil {
		return fmt.Errorf("open audit ledger: %w", err)
	}
	defer ledger.Close()
	replayed, err := engine.Replay(context.Background(), ledger)
	if err != nil {
		return fmt.Errorf("replay decisions: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(replayed); err != nil {
		return fmt.Errorf("write replay result: %w", err)
	}
	if len(replayed.Mismatches) > 0 {
		return fmt.Errorf("replay found %d decision mismatch(es)", len(replayed.Mismatches))
	}
	return nil
}

const sampleConfigUsage = `Usage: agentguard sample-config

Emits the complete conservative runtime configuration to stdout.
`

func runSampleConfig(args []string, stdout io.Writer) error {
	if hasHelp(args) {
		fmt.Fprint(stdout, sampleConfigUsage)
		return nil
	}
	if len(args) != 0 {
		return usageError{sampleConfigUsage, fmt.Errorf("unexpected argument %q", args[0])}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config.Default()); err != nil {
		return fmt.Errorf("write sample config: %w", err)
	}
	return nil
}
