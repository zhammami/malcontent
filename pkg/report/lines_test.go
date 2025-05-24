package report

import (
	"context"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestMatchStringsWithLines(t *testing.T) {
	strings := []string{"abc", "abc", "abcd"}
	lines := []int{1, 2, 3}

	gotStr, gotLines := matchStringsWithLines("rule", strings, lines)

	wantStr := []string{"abcd", "abc"}
	wantLines := []int{3, 1}

	if len(gotStr) != len(wantStr) {
		t.Fatalf("strings length got %d want %d", len(gotStr), len(wantStr))
	}
	for i := range wantStr {
		if gotStr[i] != wantStr[i] || gotLines[i] != wantLines[i] {
			t.Errorf("index %d got (%s,%d) want (%s,%d)", i, gotStr[i], gotLines[i], wantStr[i], wantLines[i])
		}
	}
}

func TestGenerateLineInfo(t *testing.T) {
	rule := `rule test { strings: $a = "bar" condition: $a }`
	comp := yarax.NewCompiler()
	if err := comp.AddString(rule, ""); err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	yrs, err := comp.GetRules()
	if err != nil {
		t.Fatalf("get rules: %v", err)
	}
	scanner := yarax.NewScanner(yrs)
	fc := []byte("foo\nbar\nbaz\n")
	mrs, err := scanner.Scan(fc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	fr, err := Generate(context.Background(), "testfile", mrs, malcontent.Config{LineInfo: true}, "", nil, fc, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(fr.Behaviors) == 0 || len(fr.Behaviors[0].MatchLines) == 0 {
		t.Fatalf("expected match lines")
	}
	if fr.Behaviors[0].MatchLines[0] != 2 {
		t.Errorf("line = %d, want 2", fr.Behaviors[0].MatchLines[0])
	}
}
