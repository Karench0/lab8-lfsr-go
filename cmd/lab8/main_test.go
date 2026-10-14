package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gamma "github.com/Karench0/lab8-lfsr-go"
)

func TestCLIEncryptAndDecrypt(t *testing.T) {
	directory := t.TempDir()
	cardPath := filepath.Join(directory, "card.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"encrypt", "-text", gamma.DefaultText, "-out", cardPath}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"decrypt", "-in", cardPath}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout.String()) != "НУЖНАТОЛЬКООДНАПАРШИВАЯОВЦАЗПТЧТОБЫИСПОРТИТЬВСЕСТАДОТЧК" {
		t.Fatalf("unexpected decryption: %s", stdout.String())
	}
}

func TestCLIDemoAndComparison(t *testing.T) {
	directory := t.TempDir()
	comparison := filepath.Join(directory, "another.txt")
	if err := os.WriteFile(comparison, []byte(gamma.Alphabet+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	reportDir := filepath.Join(directory, "report")
	if err := run([]string{"demo", "-out", reportDir, "-compare", comparison}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(filepath.Join(reportDir, "report.md"))
	if err != nil || !strings.Contains(string(report), "another.txt") {
		t.Fatal("comparison sample is absent from the report")
	}
}

func TestCLIRejectsMissingAndMalformedCards(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{"decrypt"}, {"unknown"}, {"encrypt", "-key1", "00000"}, {"demo", "unexpected"}} {
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("accepted arguments %v", args)
		}
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	for _, contents := range []string{"{} {}", "{", `{"unknown": 1}`} {
		if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"decrypt", "-in", path}, &stdout, &stderr); err == nil {
			t.Fatal("accepted a malformed card")
		}
	}
}
