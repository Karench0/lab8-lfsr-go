package gamma

import "testing"

func TestPDFRegisterExample(t *testing.T) {
	register, err := NewLFSR(RegisterConfig{PolynomialRow: 4, Seed: "110"})
	if err != nil {
		t.Fatal(err)
	}
	// An external reference: the eight rows from page 3 of the assignment PDF.
	wantStates := []string{"110", "111", "011", "101", "010", "001", "100", "110"}
	wantBits := []uint8{0, 1, 1, 1, 0, 1, 0, 0}
	for i, want := range wantStates {
		if got := register.State(); got != want {
			t.Fatalf("row %d: state %s, want %s", i+1, got, want)
		}
		if got := register.NextBit(); got != wantBits[i] {
			t.Fatalf("row %d: output %d, want %d", i+1, got, wantBits[i])
		}
	}
	if register.Period() != 7 || register.Scrambler() != "101" {
		t.Fatal("wrong period or scrambler for the PDF example")
	}
}

func TestPrimitivePolynomialsForEveryNonzeroSeed(t *testing.T) {
	for _, row := range []int{3, 4, 5, 7, 13, 22, 41} {
		polynomial, err := PolynomialByRow(row)
		if err != nil {
			t.Fatal(err)
		}
		for seed := 1; seed < 1<<polynomial.Degree; seed++ {
			config := RegisterConfig{PolynomialRow: row, Seed: binarySeed(seed, polynomial.Degree)}
			register, err := NewLFSR(config)
			if err != nil {
				t.Fatalf("row %d seed %s: %v", row, config.Seed, err)
			}
			seen := make(map[string]bool)
			for step := 0; step < (1<<polynomial.Degree)-1; step++ {
				state := register.State()
				if seen[state] {
					t.Fatalf("row %d seed %d repeats at step %d", row, seed, step)
				}
				seen[state] = true
				register.NextBit()
			}
			if register.State() != config.Seed {
				t.Fatalf("row %d did not return to the seed", row)
			}
		}
	}
}

func binarySeed(number, width int) string {
	seed := make([]byte, width)
	for i := range seed {
		seed[width-1-i] = byte('0' + (number >> i & 1))
	}
	return string(seed)
}

func TestSystemPeriodsAndCancellation(t *testing.T) {
	system, err := NewSystem(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if system.StatePeriod() != 465 || system.BitPeriod() != 465 || system.SymbolPeriod() != 93 {
		t.Fatalf("periods: %d/%d/%d", system.StatePeriod(), system.BitPeriod(), system.SymbolPeriod())
	}
	bits := make([]uint8, 930)
	for i := range bits {
		bits[i] = system.NextBit()
	}
	for i := 0; i < 465; i++ {
		if bits[i] != bits[i+465] {
			t.Fatal("output did not repeat after a full period")
		}
	}
	// Equal registers cancel completely, although the state still has period 15.
	same := RegisterConfig{PolynomialRow: 5, Seed: "1001"}
	cancelled, err := NewSystem(SystemConfig{Register1: same, Register2: same})
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.StatePeriod() != 15 || cancelled.BitPeriod() != 1 {
		t.Fatal("XOR cancellation must reduce the output period to 1")
	}
}

func TestInvalidRegisters(t *testing.T) {
	for _, config := range []RegisterConfig{{5, "0000"}, {5, "101"}, {5, "10110"}, {5, "10a1"}, {999, "1001"}} {
		if _, err := NewLFSR(config); err == nil {
			t.Errorf("accepted invalid config: %+v", config)
		}
	}
}
