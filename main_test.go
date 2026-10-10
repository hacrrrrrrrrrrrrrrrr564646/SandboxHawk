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
