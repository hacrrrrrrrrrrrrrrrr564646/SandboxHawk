// SandboxHawk is a local JavaScript mutation fuzzer for authorized V8 testing.
// It never treats a JavaScript exception alone as a native crash.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Finding struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Seed      string    `json:"seed"`
	Testcase  string    `json:"testcase"`
	Signature string    `json:"signature"`
	ExitCode  int       `json:"exit_code"`
	TimedOut  bool      `json:"timed_out"`
	Duration  string    `json:"duration"`
	CreatedAt time.Time `json:"created_at"`
	Output    string    `json:"output,omitempty"`
}

type Result struct {
	kind, signature, output string
	exitCode                int
	timedOut                bool
	duration                time.Duration
}

var sandboxViolationPattern = regexp.MustCompile(`(?im)(sandbox violation detected|sandbox violation.*detected|sandbox.*corrupt)`)
var sanitizerPattern = regexp.MustCompile(`(?im)(^==[0-9]+==ERROR: AddressSanitizer:|^SUMMARY: AddressSanitizer:|^.*runtime error: [[:alnum:]_]|^FATAL: ThreadSanitizer:|^CHECK failed:|^DCHECK failed:|^Received signal [0-9]+)`)
var sanitizerPIDPattern = regexp.MustCompile(`==[0-9]+==`)
var addressPattern = regexp.MustCompile(`0x[0-9a-fA-F]{6,}`)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" {
		usage()
		return
	}
	switch os.Args[1] {
	case "scan":
		if err := scan(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "sandboxhawk:", err)
			os.Exit(1)
		}
	case "minimize":
		if err := minimize(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "sandboxhawk:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("SandboxHawk dev (behavioral-feedback MVP)")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`SandboxHawk — local V8 JavaScript fuzzing MVP

Usage:
  sandboxhawk scan -d8 /path/to/d8 -corpus ./testdata/seeds -out ./artifacts -runs 100
  sandboxhawk minimize -d8 /path/to/d8 -input ./artifacts/crashes/crash.js -out ./minimized.js
  sandboxhawk version

The runner executes only a locally supplied d8 binary. Use a disposable test
environment and binaries you built or are authorized to test. Native edge
coverage instrumentation is not yet implemented; this MVP retains behaviorally
novel executions and deduplicates crash signatures.`)
}

func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	d8 := fs.String("d8", "d8", "path to local d8 executable")
	corpus := fs.String("corpus", "testdata/seeds", "directory of JavaScript seed files")
	outDir := fs.String("out", "artifacts", "output directory")
	runs := fs.Int("runs", 100, "maximum executions")
	timeout := fs.Duration("timeout", 2*time.Second, "timeout per execution")
	confirmations := fs.Int("confirmations", 3, "total runs required to confirm a candidate failure")
	maxBytes := fs.Int("max-bytes", 256*1024, "maximum seed size in bytes")
	seed := fs.Int64("seed", time.Now().UnixNano(), "mutation PRNG seed")
	keepOutput := fs.Bool("keep-output", false, "include output snippets in JSON findings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runs < 1 || *timeout <= 0 || *maxBytes < 1 || *confirmations < 2 || *confirmations > 10 {
		return errors.New("runs, timeout, and max-bytes must be positive; confirmations must be between 2 and 10")
	}
	binary, err := exec.LookPath(*d8)
	if err != nil {
		return fmt.Errorf("cannot find d8 executable %q: %w", *d8, err)
	}
	seeds, err := discoverSeeds(*corpus, *maxBytes)
	if err != nil {
		return err
	}
	if len(seeds) == 0 {
		return fmt.Errorf("no readable .js seeds found in %s", *corpus)
	}
	for _, dir := range []string{"crashes", "interesting", "tmp"} {
		if err := os.MkdirAll(filepath.Join(*outDir, dir), 0755); err != nil {
			return err
		}
	}
	rng := rand.New(rand.NewSource(*seed))
	seenBehavior := map[string]bool{}
	seenCrash := map[string]bool{}
	findings := make([]Finding, 0)
	crashCount, novelCount := 0, 0
	fmt.Printf("SandboxHawk | seeds=%d runs=%d timeout=%s\n", len(seeds), *runs, *timeout)
	fmt.Println("Feedback: behavioral signatures (not native edge coverage).")
	fmt.Printf("Triage: each candidate must reproduce identically in %d total runs.\n", *confirmations)

	for i := 0; i < *runs; i++ {
		base := seeds[rng.Intn(len(seeds))]
		source := mutate(base.source, rng, i)
		tmp, err := os.CreateTemp(filepath.Join(*outDir, "tmp"), "case-*.js")
		if err != nil {
			return err
		}
		if _, err = tmp.Write(source); err != nil {
			tmp.Close()
			return err
		}
		if err = tmp.Close(); err != nil {
			return err
		}
		res := execute(binary, tmp.Name(), *timeout)
		sig := res.signature
		if sig != "" && !seenBehavior[sig] {
			seenBehavior[sig] = true
			novelCount++
			dst := filepath.Join(*outDir, "interesting", fmt.Sprintf("run-%06d.js", i+1))
			_ = os.WriteFile(dst, source, 0644)
		}
		if isCandidateFailure(res) {
			confirmed, confirmationOutput := confirmFailure(binary, tmp.Name(), res, *timeout, *confirmations)
			if !confirmed {
				fmt.Printf("[unconfirmed] run=%d kind=%s seed=%s\n", i+1, res.kind, filepath.Base(base.path))
			} else {
				crashSig := findingSignature(res)
				if !seenCrash[crashSig] {
					seenCrash[crashSig] = true
					crashCount++
					name := fmt.Sprintf("%s-%s.js", res.kind, crashSig[:12])
					dst := filepath.Join(*outDir, "crashes", name)
					if err := os.WriteFile(dst, source, 0644); err != nil { return err }
					f := Finding{ID: crashSig[:12], Kind: res.kind, Seed: base.path, Testcase: dst,
						Signature: crashSig, ExitCode: res.exitCode, TimedOut: res.timedOut,
						Duration: res.duration.String(), CreatedAt: time.Now().UTC()}
					if *keepOutput { f.Output = truncate(confirmationOutput, 8000) }
					findings = append(findings, f)
					fmt.Printf("[confirmed-%s] run=%d seed=%s signature=%s\n", res.kind, i+1, filepath.Base(base.path), f.ID)
				}
			}
		}
		_ = os.Remove(tmp.Name())
		if (i+1)%25 == 0 || i+1 == *runs {
			fmt.Printf("runs=%d/%d novel-behaviors=%d unique-findings=%d\n", i+1, *runs, novelCount, len(findings))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "findings.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	if err := writeReport(filepath.Join(*outDir, "REPORT.md"), findings, *runs, novelCount); err != nil {
		return err
	}
	fmt.Printf("Done. Unique candidate findings: %d. Report: %s\n", len(findings), filepath.Join(*outDir, "REPORT.md"))
	return nil
}


func minimize(args []string) error {
	fs := flag.NewFlagSet("minimize", flag.ContinueOnError)
	d8 := fs.String("d8", "d8", "path to local d8 executable")
	input := fs.String("input", "", "candidate testcase to minimize")
	output := fs.String("out", "minimized.js", "destination for minimized testcase")
	timeout := fs.Duration("timeout", 2*time.Second, "timeout per trial")
	if err := fs.Parse(args); err != nil { return err }
	if *input == "" { return errors.New("provide -input") }
	binary, err := exec.LookPath(*d8)
	if err != nil { return fmt.Errorf("cannot find d8 executable %q: %w", *d8, err) }
	original, err := os.ReadFile(*input)
	if err != nil { return err }
	tmpDir, err := os.MkdirTemp("", "sandboxhawk-minimize-*")
	if err != nil { return err }
	defer os.RemoveAll(tmpDir)
	trialPath := filepath.Join(tmpDir, "trial.js")
	if err := os.WriteFile(trialPath, original, 0600); err != nil { return err }
	baseline := execute(binary, trialPath, *timeout)
	if baseline.kind != "crash" && baseline.kind != "sanitizer" && baseline.kind != "timeout" {
		return fmt.Errorf("input does not reproduce a candidate crash, sanitizer finding, or timeout (kind=%s)", baseline.kind)
	}
	current := append([]byte(nil), original...)
	lines := strings.SplitAfter(string(current), "\n")
	if len(lines) < 2 { lines = []string{string(current)} }
	granularity := 2
	for granularity <= len(lines) && len(lines) > 1 {
		chunk := (len(lines) + granularity - 1) / granularity
		reduced := false
		for start := 0; start < len(lines); start += chunk {
			end := start + chunk
			if end > len(lines) { end = len(lines) }
			candidateLines := append([]string{}, lines[:start]...)
			candidateLines = append(candidateLines, lines[end:]...)
			if len(candidateLines) == 0 { continue }
			candidate := strings.Join(candidateLines, "")
			if err := os.WriteFile(trialPath, []byte(candidate), 0600); err != nil { return err }
			res := execute(binary, trialPath, *timeout)
			if sameFailure(baseline, res) {
				lines = candidateLines
				current = []byte(candidate)
				reduced = true
				break
			}
		}
		if !reduced {
			if granularity >= len(lines) { break }
			granularity *= 2
		} else if granularity > 2 {
			granularity--
		}
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil { return err }
	if err := os.WriteFile(*output, current, 0644); err != nil { return err }
	fmt.Printf("Minimized %d bytes to %d bytes; preserved %s signature. Output: %s\n", len(original), len(current), baseline.kind, *output)
	return nil
}

func sameFailure(want, got Result) bool {
	if want.kind != got.kind { return false }
	if want.kind == "timeout" { return got.timedOut }
	return normalizeOutput(want.output) == normalizeOutput(got.output)
}

type sourceSeed struct {
	path   string
	source []byte
}

func discoverSeeds(root string, maxBytes int) ([]sourceSeed, error) {
	var seeds []sourceSeed
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if d.IsDir() {
			if path != root && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "crashes" || d.Name() == "artifacts") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".js") { return nil }
		info, err := d.Info()
		if err != nil { return nil }
		if info.Size() == 0 || info.Size() > int64(maxBytes) { return nil }
		b, err := os.ReadFile(path)
		if err != nil { return nil }
		seeds = append(seeds, sourceSeed{path: path, source: b})
		return nil
	})
	return seeds, err
}

func mutate(src []byte, rng *rand.Rand, iteration int) []byte {
	s := string(src)
	// Structure-preserving-ish operators: append semantic probes, duplicate a
	// statement-sized slice, mutate literals, or wrap code in a function.
	switch rng.Intn(5) {
	case 0:
		probes := []string{
			"\n(()=>{let a=[]; for(let i=0;i<8;i++) a.push({x:i}); return a.map(x=>x.x)})()",
			"\n(()=>{let x=1; for(let i=0;i<32;i++) x=(x*3+i)|0; return x})()",
			"\n(()=>{let a=new ArrayBuffer(16); let v=new DataView(a); v.setBigInt64(0, 1n); return v.getBigInt64(0)})()",
			"\n(()=>{class A{#x=1; get(){return this.#x}} return new A().get()})()",
			"\n(()=>{let a=[1.1, NaN, Infinity, -0]; return a.map(x=>Object.is(x,-0))})()",
		}
		s += probes[rng.Intn(len(probes))]
	case 1:
		s += fmt.Sprintf("\n// SandboxHawk mutation %d\n", iteration)
		s += "for (let i=0;i<4;i++) { let x = (i * 17) ^ 0x5a5a; if (x < 0) x = -x; }\n"
	case 2:
		s = "(()=>{\n" + s + "\n})()\n"
	case 3:
		replacements := [][2]string{{"0", "1"}, {"1", "0"}, {"null", "undefined"}, {"true", "false"}, {"false", "true"}}
		p := replacements[rng.Intn(len(replacements))]
		if strings.Contains(s, p[0]) { s = strings.Replace(s, p[0], p[1], 1) } else { s += "\n" + p[0] + ";" }
	case 4:
		s += "\n(()=>{let o={}; for(let i=0;i<20;i++) o['k'+i]=i; return Reflect.ownKeys(o)})()\n"
	}
	return []byte(s)
}

func execute(binary, testcase string, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(ctx, binary, testcase)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var output bytes.Buffer
	limited := &limitWriter{w: &output, remaining: 128 * 1024}
	cmd.Stdout, cmd.Stderr = limited, limited
	err := cmd.Run()
	res := Result{duration: time.Since(start), exitCode: 0, kind: "ok"}
	if ctx.Err() == context.DeadlineExceeded {
		res.kind, res.timedOut, res.exitCode = "timeout", true, -1
	} else if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.exitCode = ee.ExitCode()
			signaled := false
			if runtime.GOOS != "windows" {
				if status, ok := ee.Sys().(syscall.WaitStatus); ok {
					signaled = status.Signaled()
				}
			}
			if signaled {
				res.kind = "crash"
			} else if res.exitCode != 0 {
				// d8 commonly exits non-zero for a JS exception. Only classify
				// it as a crash if output carries a native-failure signature.
				res.kind = "exception"
			}
		} else {
			res.kind, res.exitCode = "crash", -1
		}
	}
	res.output = output.String()
	// Text alone is not enough: JS can print sanitizer-looking strings.
	// Require a non-zero exit before classifying a sanitizer diagnostic.
	res.kind = classifyOutput(res.kind, res.exitCode, res.output)
	res.signature = hashString(res.kind + "|" + normalizeOutput(res.output) + "|" + fmt.Sprint(res.exitCode))
	return res
}

func classifyOutput(currentKind string, exitCode int, output string) string {
	// A sandbox-violation label requires both a failing process and a
	// recognized V8-style diagnostic. Text emitted by a successful d8 run
	// must never be enough to create this finding.
	if exitCode != 0 && sandboxViolationPattern.MatchString(output) {
		return "sandbox_violation"
	}
	if exitCode != 0 && sanitizerPattern.MatchString(output) {
		return "sanitizer"
	}
	return currentKind
}

func isCandidateFailure(r Result) bool {
	return r.kind == "crash" || r.kind == "timeout" || r.kind == "sanitizer" || r.kind == "sandbox_violation"
}

func findingSignature(r Result) string {
	if r.kind == "timeout" { return hashString("timeout") }
	return hashString(r.kind + "|" + normalizeOutput(r.output) + "|" + fmt.Sprint(r.exitCode))
}

// A candidate is accepted only if each retry reproduces the same failure class
// and, except for timeouts, the same normalized failure signature.
func confirmFailure(binary, testcase string, baseline Result, timeout time.Duration, totalRuns int) (bool, string) {
	outputs := []string{baseline.output}
	for i := 1; i < totalRuns; i++ {
		next := execute(binary, testcase, timeout)
		if !sameFailure(baseline, next) {
			return false, strings.Join(outputs, "\n--- retry ---\n")
		}
		if baseline.kind != "timeout" && findingSignature(baseline) != findingSignature(next) {
			return false, strings.Join(outputs, "\n--- retry ---\n")
		}
		outputs = append(outputs, next.output)
	}
	return true, strings.Join(outputs, "\n--- confirmed retry ---\n")
}

type limitWriter struct { w io.Writer; remaining int }
func (l *limitWriter) Write(p []byte) (int, error) {
	n := len(p)
	if l.remaining <= 0 { return n, nil }
	if len(p) > l.remaining { p = p[:l.remaining] }
	_, err := l.w.Write(p)
	l.remaining -= len(p)
	return n, err
}

func normalizeOutput(s string) string {
	s = sanitizerPIDPattern.ReplaceAllString(s, "==PID==")
	s = addressPattern.ReplaceAllString(s, "0xADDR")
	lines := strings.Split(strings.TrimSpace(s), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" { continue }
		if strings.Contains(line, "run-") || strings.Contains(line, "case-") { continue }
		out = append(out, line)
		if len(out) == 8 { break }
	}
	return strings.Join(out, "\n")
}
func hashString(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func truncate(s string, n int) string { if len(s) > n { return s[:n] }; return s }

func writeReport(path string, findings []Finding, runs, novel int) error {
	var b strings.Builder
	b.WriteString("# SandboxHawk Run Report\n\n")
	fmt.Fprintf(&b, "- Executions: %d\n- Novel behavioral signatures: %d\n- Unique candidate findings: %d\n\n", runs, novel, len(findings))
	b.WriteString("> Behavioral novelty is not native edge coverage. Findings are candidates for manual reproduction; a timeout or crash does not by itself prove a V8 sandbox violation.\n\n")
	if len(findings) == 0 { b.WriteString("No unique crash, timeout, sanitizer, or sandbox-violation candidates were observed in this run.\n"); return os.WriteFile(path, []byte(b.String()), 0644) }
	b.WriteString("| ID | Kind | Exit | Duration | Testcase |\n|---|---|---:|---:|---|\n")
	for _, f := range findings { fmt.Fprintf(&b, "| %s | %s | %d | %s | `%s` |\n", f.ID, f.Kind, f.ExitCode, f.Duration, f.Testcase) }
	return os.WriteFile(path, []byte(b.String()), 0644)
}
