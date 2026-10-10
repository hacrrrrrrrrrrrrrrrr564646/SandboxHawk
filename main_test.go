package main

import (
	"math/rand"
	"strings"
	"testing"
)

func TestHashStringStable(t *testing.T) {
	if hashString("same") != hashString("same") {
		t.Fatal("same input must produce same hash")
	}
	if hashString("same") == hashString("different") {
		t.Fatal("different inputs should not share a SHA-256 digest")
	}
}

func TestMutateProducesSource(t *testing.T) {
	for i := int64(0); i < 20; i++ {
		got := mutate([]byte("let x = 1;"), rand.New(rand.NewSource(i)), int(i))
		if len(got) == 0 {
			t.Fatalf("mutation %d returned empty source", i)
		}
	}
}

func TestNormalizeOutputRemovesBlankLines(t *testing.T) {
	got := normalizeOutput("\n  one  \n\n two \n")
	if strings.Contains(got, "\n\n") || got != "one\ntwo" {
		t.Fatalf("unexpected normalized output: %q", got)
	}
}

func TestSanitizerRequiresFailureAndCanonicalDiagnostic(t *testing.T) {
	canonical := "==123==ERROR: AddressSanitizer: heap-buffer-overflow"
	if got := classifyOutput("ok", 0, canonical); got != "ok" {
		t.Fatalf("successful process must not become sanitizer finding: %q", got)
	}
	if got := classifyOutput("exception", 1, "Error: AddressSanitizer is mentioned in ordinary text"); got != "exception" {
		t.Fatalf("non-canonical text must not become sanitizer finding: %q", got)
	}
	if got := classifyOutput("crash", 1, canonical); got != "sanitizer" {
		t.Fatalf("canonical sanitizer output on failing process should be classified, got %q", got)
	}
}

func TestCandidateFailureKinds(t *testing.T) {
	for _, kind := range []string{"crash", "timeout", "sanitizer"} {
		if !isCandidateFailure(Result{kind: kind}) {
			t.Errorf("%q should be a candidate failure", kind)
		}
	}
	for _, kind := range []string{"ok", "exception"} {
		if isCandidateFailure(Result{kind: kind}) {
			t.Errorf("%q must not be reported as a candidate failure", kind)
		}
	}
}
