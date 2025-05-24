package report

import (
	"strings"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
)

func TestCalculateLineNumber(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		offset   int
		expected int
	}{
		{
			name:     "empty content",
			content:  "",
			offset:   0,
			expected: 1,
		},
		{
			name:     "first line",
			content:  "hello world",
			offset:   0,
			expected: 1,
		},
		{
			name:     "first line middle",
			content:  "hello world",
			offset:   6,
			expected: 1,
		},
		{
			name:     "second line",
			content:  "hello\nworld",
			offset:   6,
			expected: 2,
		},
		{
			name:     "third line",
			content:  "hello\nworld\nfoo bar",
			offset:   12,
			expected: 3,
		},
		{
			name:     "multiple newlines",
			content:  "line1\nline2\nline3\nline4",
			offset:   18,
			expected: 4,
		},
		{
			name:     "offset at newline",
			content:  "hello\nworld",
			offset:   5,
			expected: 1,
		},
		{
			name:     "offset beyond content",
			content:  "hello",
			offset:   100,
			expected: 0,
		},
		{
			name:     "negative offset",
			content:  "hello",
			offset:   -1,
			expected: 0,
		},
		{
			name:     "windows line endings",
			content:  "hello\r\nworld\r\ntest",
			offset:   14,
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateLineNumber([]byte(tt.content), tt.offset)
			if got != tt.expected {
				t.Errorf("calculateLineNumber() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// MockMatch implements a minimal yarax.Match interface for testing
type MockMatch struct {
	offset uint64
	length uint64
}

func (m MockMatch) Offset() uint64 {
	return m.offset
}

func (m MockMatch) Length() uint64 {
	return m.length
}

func (m MockMatch) XorKey() uint8 {
	return 0
}

// MockPattern implements a minimal yarax.Pattern interface for testing
type MockPattern struct {
	identifier string
	matches    []yarax.Match
}

func (p MockPattern) Identifier() string {
	return p.identifier
}

func (p MockPattern) Matches() []yarax.Match {
	return p.matches
}

func TestMatchProcessorWithLineInfo(t *testing.T) {
	content := []byte("first line\nsecond line\nthird line")
	
	matches := []yarax.Match{
		MockMatch{offset: 0, length: 5},    // "first" at line 1
		MockMatch{offset: 11, length: 6},   // "second" at line 2
		MockMatch{offset: 23, length: 5},   // "third" at line 3
	}
	
	patterns := []yarax.Pattern{
		MockPattern{identifier: "test_pattern", matches: matches},
	}
	
	// Test with line info enabled
	processor := newMatchProcessor(content, matches, patterns, true)
	result := processor.process()
	
	if len(result.Strings) != 3 {
		t.Errorf("Expected 3 strings, got %d", len(result.Strings))
	}
	
	if len(result.LineNumbers) != 3 {
		t.Errorf("Expected 3 line numbers, got %d", len(result.LineNumbers))
	}
	
	expectedStrings := []string{"first", "second", "third"}
	expectedLineNumbers := []int{1, 2, 3}
	
	for i := range result.Strings {
		if result.Strings[i] != expectedStrings[i] {
			t.Errorf("String[%d] = %q, want %q", i, result.Strings[i], expectedStrings[i])
		}
		if result.LineNumbers[i] != expectedLineNumbers[i] {
			t.Errorf("LineNumber[%d] = %d, want %d", i, result.LineNumbers[i], expectedLineNumbers[i])
		}
	}
	
	// Test with line info disabled
	processor = newMatchProcessor(content, matches, patterns, false)
	result = processor.process()
	
	if len(result.LineNumbers) != 0 {
		t.Errorf("Expected no line numbers when lineInfo=false, got %d", len(result.LineNumbers))
	}
}

func TestMatchProcessorWithUnprintableChars(t *testing.T) {
	content := []byte("hello\x00world\nsecond line")
	
	matches := []yarax.Match{
		MockMatch{offset: 0, length: 11},   // "hello\x00world" - contains unprintable
		MockMatch{offset: 12, length: 6},   // "second" - printable
	}
	
	patterns := []yarax.Pattern{
		MockPattern{identifier: "test_pattern", matches: matches},
	}
	
	processor := newMatchProcessor(content, matches, patterns, true)
	result := processor.process()
	
	// First match should return pattern identifier instead of the string
	if len(result.Strings) < 2 {
		t.Fatalf("Expected at least 2 strings, got %d", len(result.Strings))
	}
	
	// When unprintable chars are found, pattern identifier is returned
	if result.Strings[0] != "test_pattern" {
		t.Errorf("Expected pattern identifier for unprintable match, got %q", result.Strings[0])
	}
	
	if result.Strings[1] != "second" {
		t.Errorf("Expected 'second', got %q", result.Strings[1])
	}
	
	// Line numbers should still be calculated correctly
	if len(result.LineNumbers) != 2 {
		t.Fatalf("Expected 2 line numbers, got %d", len(result.LineNumbers))
	}
	
	if result.LineNumbers[0] != 1 {
		t.Errorf("Expected line 1 for first match, got %d", result.LineNumbers[0])
	}
	
	if result.LineNumbers[1] != 2 {
		t.Errorf("Expected line 2 for second match, got %d", result.LineNumbers[1])
	}
}

func BenchmarkCalculateLineNumber(b *testing.B) {
	// Create a large file with many lines
	lines := make([]string, 10000)
	for i := range lines {
		lines[i] = "This is a test line with some content"
	}
	content := []byte(strings.Join(lines, "\n"))
	
	// Test various offsets
	offsets := []int{100, 1000, 10000, 50000, 100000}
	
	b.ResetTimer()
	for b.Loop() {
		for _, offset := range offsets {
			_ = calculateLineNumber(content, offset)
		}
	}
}