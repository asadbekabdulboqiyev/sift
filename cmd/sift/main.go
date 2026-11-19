package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/cliux"
	"github.com/asadbekabdulboqiyev/sift/internal/version"
)

// buildVersion is the release version, overridden at build time via ldflags.
// Falls back to internal/version.Version (from VERSION file / debug.ReadBuildInfo).
var buildVersion = version.Version

// knownCommands is the source of truth for command suggestions and the
// "unknown command" listing. Keep in sync with the switch in main().
var knownCommands = []string{
	"run", "replay", "scan", "dashboard", "master", "worker",
	"demo-store", "pentest", "simulate", "xray", "bounty",
	"fuzz", "dirbust", "jwt", "graphql", "websocket",
	"crawl", "subdomain", "portscan", "sslscan",
	"authorize", "audit", "healthcheck", "keygen", "trust", "verify", "certificate", "audit360", "admin",
	"test", "secure", "evidence", // alias groups; see commandGroups
	"help", "version",
}

// commandGroup is an additive alias: a short group name that forwards to a
// fixed set of existing commands. A group name never shadows a real command.
type commandGroup struct {
	summary  string
	commands []string
}

// contains reports whether name is a real command exposed by the group.
func (g commandGroup) contains(name string) bool {
	for _, c := range g.commands {
		if c == name {
			return true
		}
	}
	return false
}

// commandGroups lists the alias groups exposed in addition to the flat command
// set. Adding a group never removes or renames a direct command.
var commandGroups = map[string]commandGroup{
	"test": {
		summary:  "load and behavior testing",
		commands: []string{"run", "replay", "simulate", "healthcheck"},
	},
	"secure": {
		summary: "security scanning and assessment",
		commands: []string{
			"scan", "pentest", "xray", "fuzz", "dirbust", "jwt", "graphql",
			"websocket", "crawl", "subdomain", "portscan", "sslscan",
			"bounty", "audit360",
		},
	},
	"evidence": {
		summary:  "cryptographic evidence and authorization handling",
		commands: []string{"keygen", "trust", "verify", "certificate", "audit", "authorize"},
	},
}

func main() {
	// Resolve additive alias groups before the existing dispatch. Direct
	// command names never enter this path, so their parsing is unchanged.
	resolveGroupAlias()

	// Check for subcommands
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		switch cmd {
		case "run":
			os.Args = os.Args[1:] // keep "run" as [0] for flagset
			cmdRun()
			return
		case "replay":
			cmdReplay()
			return
		case "scan":
			cmdScan()
			return
		case "dashboard":
			cmdDashboard()
			return
		case "master":
			cmdMaster()
			return
		case "worker":
			cmdWorker()
			return
		case "pentest":
			cmdPentest()
			return
		case "simulate":
			cmdSimulate()
			return
		case "xray":
			cmdXray()
			return
		case "bounty":
			cmdBounty()
			return
		case "fuzz":
			cmdFuzz()
			return
		case "dirbust":
			cmdDirBust()
			return
		case "jwt":
			cmdJWT()
			return
		case "graphql":
			cmdGraphQL()
			return
		case "websocket":
			cmdWebSocket()
			return
		case "crawl":
			cmdCrawl()
			return
		case "subdomain":
			cmdSubdomain()
			return
		case "portscan":
			cmdPortScan()
			return
		case "sslscan":
			cmdSSLScan()
			return
		case "demo-store":
			cmdDemoStore()
			return
		case "authorize":
			cmdAuthorize()
			return
		case "audit":
			cmdAudit()
			return
		case "healthcheck":
			cmdHealthcheck()
			return
		case "keygen":
			cmdKeygen()
			return
		case "trust":
			cmdTrust()
			return
		case "verify":
			cmdVerify()
			return
		case "certificate":
			cmdCertificate()
			return
		case "audit360":
			cmdAudit360()
			return
		case "admin":
			cmdAdmin()
			return
		case "help", "--help", "-h":
			printFullHelp()
			return
		case "version", "--version", "-v":
			fmt.Printf("Sift v%s\n", version.Full())
			return
		default:
			unknownCommand(cmd)
			exitProcess(2)
		}
	}

	// No subcommand: if a TTY is attached, show the interactive mode picker
	// (CLI vs Web Server). Otherwise fall back to run for script/CI usage.
	if isInteractiveTerminal() {
		interactivePicker()
		return
	}
	cmdRun()
}

// resolveGroupAlias rewrites os.Args when os.Args[1] names an alias group.
// Direct command names are left untouched, so the switch in main (including
// run's own os.Args reshaping) sees exactly the argv a direct invocation would.
// An unknown or missing subcommand prints a group-specific error and exits 2
// before any command function runs, so no network activity can start.
func resolveGroupAlias() {
	if len(os.Args) < 2 {
		return
	}
	group, ok := commandGroups[os.Args[1]]
	if !ok {
		return
	}

	sub := ""
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	if !group.contains(sub) {
		unknownGroupSubcommand(os.Args[1], sub, group)
		exitProcess(2)
		return
	}

	// Drop the group token. The real command now sits at index 1, the shape
	// every command function already expects (run reshapes it once more).
	os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
}

// unknownGroupSubcommand reports an invalid (or missing) subcommand for an
// alias group, listing what that group offers plus an overview of all groups.
// It only prints: no command is dispatched and nothing touches the network.
func unknownGroupSubcommand(group, sub string, g commandGroup) {
	w := os.Stderr
	if sub == "" {
		fmt.Fprintf(w, "Error: group %q requires a subcommand.\n\n", group)
	} else {
		fmt.Fprintf(w, "Error: unknown command %q for group %q.\n\n", sub, group)
	}

	fmt.Fprintf(w, "Available subcommands for 'Sift %s' (%s):\n", group, g.summary)
	for _, c := range g.commands {
		fmt.Fprintf(w, "   Sift %s %s\n", group, c)
	}

	fmt.Fprintf(w, "\nAll command groups:\n")
	for _, name := range []string{"test", "secure", "evidence"} {
		fmt.Fprintf(w, "   %-9s %s\n", name, commandGroups[name].summary)
	}
	fmt.Fprintf(w, "\nDirect commands still work, for example 'Sift %s ...'.\n", g.commands[0])
	fmt.Fprintf(w, "Run 'Sift --help' for every command and flag.\n")
}

// unknownCommand reports an unrecognized subcommand with a "did you mean"
// suggestion, the command list, and a pointer to --help. Exit code 2 matches
// the usage-error convention used across the CLI.
func unknownCommand(cmd string) {
	w := os.Stderr
	if cliux.IsColorable(w) {
		fmt.Fprintf(w, "\x1b[1;31mError:\x1b[0m unknown command %q.\n\n", cmd)
	} else {
		fmt.Fprintf(w, "Error: unknown command %q.\n\n", cmd)
	}
	if suggs := cliux.Suggestions(cmd, knownCommands, 3); len(suggs) > 0 {
		fmt.Fprintf(w, "Did you mean: %s?\n\n", strings.Join(suggs, " | "))
	}
	fmt.Fprintf(w, "Run '%s' with one of these commands:\n", filepath.Base(os.Args[0]))
	for _, c := range knownCommands {
		fmt.Fprintf(w, "   %s\n", c)
	}
	fmt.Fprintf(w, "\nRun 'Sift --help' to see all commands, flags and examples.\n")
}

// shouldFailGate reports whether the measured error rate should trip the SLA
// gate. A threshold of 0 (or negative) disables the gate. The gate fails only
// when the rate is strictly greater than the threshold.
func shouldFailGate(ratePct, threshold float64) bool {
	return threshold > 0 && ratePct > threshold
}

func printFullHelp() {
	fmt.Fprintf(os.Stderr, `
Sift %s — Ultra-Fast Load Testing & Security Suite

 USAGE
   Sift <command> [flags]

═══════════════════════════════════════════════════════════════════════
 COMMANDS
═══════════════════════════════════════════════════════════════════════
   run         HTTP/gRPC/WebSocket load test (default)
   replay      Replay real traffic from PCAP/HAR captures
   scan        TLS/WAF deep scanner + fingerprinting
   dashboard   Real-time web dashboard with WebSocket
   master      Distributed mode — master coordinator
   worker      Distributed mode — worker node
   demo-store  Launch bundled VoltStore demo (VeriGate ON)
               subcommands: status | stop
   pentest     1-click professional security assessment
   simulate    Capacity digital twin / what-if simulation from Sift reports
   xray        Opt-in host observability (aggregate /proc or runtime) and correlation
   bounty      Verifiable bug-bounty/triage evidence package workflow
   authorize   Manage target authorizations (allow-list + approvals)
   audit       Show or verify the authorization audit trail
   keygen      Create a Sift coordinator keypair (Ed25519, PEM)
   trust       Manage the issuer trust store (pin who you believe)
   verify      Verify a Sift (vpmp/v1) evidence bundle
   certificate Issue/verify an Ed25519-signed security assessment certificate
   audit360    Verify a sealed Sift 360° audit report
   admin       Local admin area: code, status, unlock/lock the bypass switch
   help        Show this help
   version     Show version

═══════════════════════════════════════════════════════════════════════
 COMMAND GROUPS (additive shortcuts; direct commands above still work)
═══════════════════════════════════════════════════════════════════════
   test       run | replay | simulate | healthcheck
   secure     scan | pentest | xray | fuzz | dirbust | jwt | graphql
              websocket | crawl | subdomain | portscan | sslscan | bounty
              audit360
   evidence   keygen | trust | verify | certificate | audit | authorize

   Example: Sift secure pentest --target https://example.com --authorized TICKET-1

═══════════════════════════════════════════════════════════════════════
 INDIVIDUAL SCANNERS (each is scope-gated like pentest)
═══════════════════════════════════════════════════════════════════════
   fuzz        Coverage-aware HTTP fuzzer (path/query/body/header mutations)
   dirbust     Directory/file brute-forcer
   jwt         Offline JWT weakness analyzer (no network, no gate)
   graphql     GraphQL introspection scanner
   websocket   WebSocket security tester
   crawl       Site spider — discover links, forms and endpoints
   subdomain   Passive subdomain enumeration (crt.sh + DNS)
   portscan    TCP port & service scanner
   sslscan     TLS certificate & configuration analyzer

   Shared gate flags: --authorized --policy --audit-log --notify-webhook
                      --allow --allow-all --dry-run --rate --budget
   Result output:     --json, --output-json <path>  (JSON to stdout / file)

═══════════════════════════════════════════════════════════════════════
 RUN FLAGS — Load Test
═══════════════════════════════════════════════════════════════════════
   --url string             Target URL (required if no --config)
   --config string          YAML scenario file (alternative to --url)
   --users int              Virtual users (default: 10)
   --duration int           Test duration in seconds (default: 10)
   --ramp-up int            Ramp-up time in seconds (default: 0)
   --method string          HTTP method: GET, POST, PUT, DELETE, PATCH
   --data string            Request body (JSON)
   --header string          Header: -header "Key: Value" (repeatable)
   --timeout int            Request timeout in seconds (default: 10)
   --keep-alive             Reuse TCP connections (default: true)
   --name string            Report name (default: "stress-test")

   Load Profiles:
   --profile string         steady|soak|linear-ramp|spike|wave|constant-rps
   --target-rps int         Target RPS for constant-rps mode
   --spike-users int        Spike peak users
   --spike-warmup int       Spike warmup seconds
   --spike-hold int         Spike hold seconds
   --wave-period int        Wave period seconds

   Performance:
   --pre-warm               Pre-establish TCP connections before test
   --pre-warm-conns int     Number of pre-warmed connections (default: users)
   --quiet                  Suppress live progress bar

   Accuracy:
   --coordinated-omission   Correct paced runs for coordinated omission (adds
                            the schedule skew a request waited back to latency)

   SLA Gate (CI/CD):
   --expect-p99-ms float    Max P99 latency in ms (exit 2 if exceeded)
   --expect-error-rate float Max error rate %% (exit 2 if exceeded)
   --expect-min-rps float   Min RPS threshold (exit 2 if below)

   Comparison:
   --compare string         Baseline report JSON for comparison
   --regress-pct float      Max regression %% before exit 2 (default: 20)

   Output:
   --timeline               Save per-second CSV timeline
   --report-dir string      Report output directory (default: "reports")

   Mode:
   --mode string            cli (terminal report, default) | dashboard (real-time web)
   --listen string          Dashboard listen address (default: 127.0.0.1:8888, with --mode dashboard)

═══════════════════════════════════════════════════════════════════════
 REPLAY FLAGS — Traffic Replay
═══════════════════════════════════════════════════════════════════════
   -input string            PCAP or HAR capture file (required)
   -rate float              Speed multiplier: 1.0=realtime, 10.0=10x (default: 1.0)
   -concurrency int         Parallel workers (default: 5)
   -tls-key string          TLS private key for HTTPS decryption
   -base-url string         Override target URL
   -validate                Enable response assertions
   -assert-status int       Expected HTTP status code
   -assert-regex string     Expected response body regex
   -output-json string      Save results to JSON file
   -report-dir string       Report output directory

   Filters:
   -filter-methods string   Comma-separated HTTP methods to include
   -filter-urls string      URL pattern (regex)
   -filter-min-status int   Min status code
   -filter-max-status int   Max status code

═══════════════════════════════════════════════════════════════════════
 SCAN FLAGS — Security Scanner
═══════════════════════════════════════════════════════════════════════
   -target string           Target host:port (required)
   -tls                     Run TLS scanner
   -waf                     Run WAF detection
   -http                    Run HTTP fingerprinting
   -all                     Run all scanners
   -json string             Save results to JSON file

═══════════════════════════════════════════════════════════════════════
 DASHBOARD FLAGS — Web Dashboard
═══════════════════════════════════════════════════════════════════════
   -listen string           Address to listen on (default: "127.0.0.1:8888")

═══════════════════════════════════════════════════════════════════════
 MASTER FLAGS — Distributed Coordinator
═══════════════════════════════════════════════════════════════════════
   --workers string         Comma-separated worker addresses (required)
   --url string             Target URL (required)
   --users int              Total virtual users (default: 10)
   --duration int           Test duration in seconds (default: 10)
   --listen string          Master gRPC address (default: ":50051")
   --compare string         Baseline report for comparison
   --regress-pct float      Max regression %% (default: 20)

═══════════════════════════════════════════════════════════════════════
 WORKER FLAGS — Distributed Worker
═══════════════════════════════════════════════════════════════════════
   --listen string          Worker gRPC address (default: ":50052")

═══════════════════════════════════════════════════════════════════════
 PENTEST FLAGS — 1-Click Security Assessment (14 phases)
═══════════════════════════════════════════════════════════════════════
   --target string        Target URL or domain (required)
   --depth int            Scan depth: 1=quick, 2=standard, 3=deep (default: 2)
   --output string        Output directory (default: reports/pentest-{target}-{ts})
   --format string        Report format: html,json,markdown,pdf,professional,all
                          (pdf=client-ready PDF, professional=PDF+HTML+MD) (default: all)
   --scope string         Scope: full,web,network (default: full)
   --threads int          Parallel threads (default: 10)
   --timeout int          Request timeout in seconds (default: 10)
   --skip-load-test       Skip load testing phase
   --verbose              Show detailed progress

 AUTHENTICATED SCANNING — test behind login (where most bugs live)
   --auth-form URL        Form login URL, e.g. https://site.com/login
   --auth-user string     Login username
   --auth-pass string     Login password
   --auth-user-field      Username field name (default: username)
   --auth-pass-field      Password field name (default: password)
   --auth-cookie string   Raw cookie header instead of form login
   --auth-header string   Static header 'Name: Value' (e.g. Authorization: Bearer x)

 ATTACK SURFACE & INTEL
   --crawl                Crawl target to discover endpoints/forms (default: true)
   --max-pages int        Max pages to crawl (default: 50)
   --nvd                  Query live NVD database, 240K+ CVEs (default: true)
   --compliance string    Frameworks: pci-dss,soc2,iso27001,none (default: all three)

═══════════════════════════════════════════════════════════════════════
 QUICK EXAMPLES
═══════════════════════════════════════════════════════════════════════

  # Simple load test
  Sift run --url https://api.example.com --users 100 --duration 60

  # Constant RPS mode (1000 requests/sec)
  Sift run --url https://api.example.com --target-rps 1000 --duration 30

  # Pre-warm connections (zero handshake overhead)
  Sift run --url https://api.example.com --users 100 --pre-warm

  # SLA gate for CI/CD (exit code 2 on failure)
  Sift run --url https://api.example.com --users 50 --duration 30 \
    --expect-p99-ms 200 --expect-error-rate 1

  # Compare with baseline (detect regressions)
  Sift run --url https://api.example.com --users 50 --duration 30 \
    --compare reports/baseline.json --regress-pct 20

  # Replay production traffic at 10x speed
  Sift replay -input traffic.har -rate 10x -concurrency 20

  # Scan server security
  Sift scan -target example.com -all

  # Start web dashboard (loopback only by default)
  Sift dashboard

  # Expose on all interfaces (warns: no auth)
  Sift dashboard -listen :8888

  # Distributed load test
  Sift master --workers host1:50052,host2:50052 --url URL --users 1000
  Sift worker --listen :50052

  # YAML scenario file
  Sift run --config examples/login-flow.yaml

  # Spike test
  Sift run --url https://api.example.com --users 100 --duration 60 \
    --profile spike --spike-users 500 --spike-warmup 10 --spike-hold 20

  # 1-click security assessment
  Sift pentest --target https://example.com --depth 2 --verbose

  # Individual scanners (each is scope-gated; add --authorized <ticket> for pentest-grade ops)
  Sift fuzz    --target https://example.com --path /item/{id} --mutations 200
  Sift dirbust --target https://example.com
  Sift crawl   --target https://example.com --depth 3
  Sift subdomain --target https://example.com
  Sift portscan --target https://example.com --ports 22,80,443
  Sift sslscan --target https://example.com
  Sift graphql --target https://example.com/graphql
  Sift websocket --url wss://example.com/socket

  # Offline JWT analysis (no network, no gate) — token is never echoed back
  Sift jwt --token eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.

  # Preview any scanner's probe policy without sending a byte
  Sift dirbust --target https://example.com --dry-run

  # Quiet mode (no progress bar, for scripts)
  Sift run --url https://api.example.com --users 100 --duration 60 --quiet

  # Real-time web dashboard output (open browser, press Start)
  Sift run --url https://api.example.com --users 100 --duration 60 --mode dashboard

═══════════════════════════════════════════════════════════════════════
 WARNING: Only test systems you own or have explicit permission to test.
          Unauthorized load testing is illegal.
═══════════════════════════════════════════════════════════════════════
`, buildVersion)
}
