package gamma

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistogramKnownCountsAndUniformity(t *testing.T) {
	histogram, err := Histogram("ААБВ")
	if err != nil {
		t.Fatal(err)
	}
	if len(histogram) != 32 || histogram[0].Count != 2 || histogram[0].Share != 0.5 || histogram[1].Share != 0.25 || histogram[3].Count != 0 {
		t.Fatal("incorrect frequency counts")
	}
	sum := 0.0
	for _, bin := range histogram {
		sum += bin.Share
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Fatal("frequencies do not sum to 1")
	}
	uniform, err := Analyze(Alphabet)
	if err != nil || uniform.Entropy != 5 || uniform.Distance != 0 {
		t.Fatalf("uniform statistics: %+v, %v", uniform, err)
	}
	constant, _ := Analyze("АААА")
	if constant.Entropy != 0 || constant.Distance != 31.0/32 {
		t.Fatal("incorrect constant-text statistics")
	}
	empty, _ := Histogram("")
	for _, bin := range empty {
		if bin.Count != 0 || bin.Share != 0 {
			t.Fatal("empty histogram must contain zero counts")
		}
	}
	if _, err := Histogram("!"); err == nil {
		t.Fatal("unsupported histogram symbol accepted")
	}
}

func TestReportContainsReversibleCardAndFullTraces(t *testing.T) {
	directory := t.TempDir()
	if err := WriteReport(directory, DefaultText, DefaultConfig(), nil); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, "card.json"))
	if err != nil {
		t.Fatal(err)
	}
	var card Card
	if err := json.Unmarshal(contents, &card); err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(card)
	if err != nil || plain != expectedPlain {
		t.Fatal("saved card cannot restore the phrase")
	}
	for name, wantRows := range map[string]int{"register1.csv": 33, "register2.csv": 17, "system.csv": 467, "encryption.csv": 56, "task1-variant1.csv": 17, "task2-variant1.csv": 17, "frequencies.csv": 65} {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(strings.NewReader(string(contents))).ReadAll()
		if err != nil || len(rows) != wantRows {
			t.Fatalf("%s rows: %d, want %d; %v", name, len(rows), wantRows, err)
		}
		if name == "system.csv" && strings.Join(rows[1][1:], ",") != strings.Join(rows[len(rows)-1][1:], ",") {
			t.Fatal("system trace does not demonstrate state repetition")
		}
	}
	svg, err := os.ReadFile(filepath.Join(directory, "histograms.svg"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(strings.NewReader(string(svg)))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid SVG: %v", err)
		}
	}
}
