// Package gamma implements the educational LFSR cipher from laboratory 8.
package gamma

import (
	"fmt"
	"math/bits"
)

// Polynomial is an entry from table П1.1 of «Таблица ЛР_8».
// Mask includes the constant term: x^5+x^2+1 is binary 100101.
type Polynomial struct {
	Row    int    `json:"table_row"`
	Degree int    `json:"degree"`
	Mask   uint64 `json:"mask"`
	Name   string `json:"name"`
}

// PolynomialByRow deliberately exposes a small, checked selection from the table.
// Irreducibility alone does not guarantee an M-sequence; periods are checked below.
func PolynomialByRow(row int) (Polynomial, error) {
	polynomials := map[int]Polynomial{
		3:  {3, 3, 0b1011, "x^3 + x + 1"},
		4:  {4, 3, 0b1101, "x^3 + x^2 + 1"},
		5:  {5, 4, 0b10011, "x^4 + x + 1"},
		7:  {7, 5, 0b100101, "x^5 + x^2 + 1"},
		13: {13, 6, 0b1000011, "x^6 + x + 1"},
		22: {22, 7, 0b10000011, "x^7 + x + 1"},
		41: {41, 8, 0b100011101, "x^8 + x^4 + x^3 + x^2 + 1"},
	}
	p, ok := polynomials[row]
	if !ok {
		return Polynomial{}, fmt.Errorf("строка %d не поддерживается; доступны 3, 4, 5, 7, 13, 22, 41", row)
	}
	return p, nil
}

type RegisterConfig struct {
	PolynomialRow int    `json:"polynomial_row"`
	Seed          string `json:"seed"`
}

type LFSR struct {
	polynomial Polynomial
	state      uint64
	initial    uint64
	period     int
}

func NewLFSR(config RegisterConfig) (*LFSR, error) {
	p, err := PolynomialByRow(config.PolynomialRow)
	if err != nil {
		return nil, err
	}
	if len(config.Seed) != p.Degree {
		return nil, fmt.Errorf("начальный ключ для строки %d должен содержать %d бит", p.Row, p.Degree)
	}
	var seed uint64
	for _, digit := range config.Seed {
		if digit != '0' && digit != '1' {
			return nil, fmt.Errorf("начальный ключ должен состоять из 0 и 1")
		}
		seed = seed<<1 | uint64(digit-'0')
	}
	if seed == 0 {
		return nil, fmt.Errorf("нулевой ключ запрещён: регистр останется в нулевом состоянии")
	}
	r := &LFSR{polynomial: p, state: seed, initial: seed}
	probe := *r
	for step := 1; step <= (1<<p.Degree)-1; step++ {
		probe.NextBit()
		if probe.state == seed {
			r.period = step
			break
		}
	}
	if r.period != (1<<p.Degree)-1 {
		return nil, fmt.Errorf("многочлен %s не даёт М-последовательность: период %d", p.Name, r.period)
	}
	return r, nil
}

// NextBit outputs the rightmost bit BEFORE the shift, as in the PDF example.
// For p(x)=x^m + sum(a_i*x^i), the recurrence is
// b(t+m) = XOR(a_i * b(t+i)), i=0..m-1. The state stores b(t+i)
// in bit i; cells are numbered from the right, starting at 1.
// The leading term is omitted from the tap mask; feedback enters the leftmost cell.
func (r *LFSR) NextBit() uint8 {
	output := uint8(r.state & 1)
	feedback := uint64(bits.OnesCount64(r.state&r.tapMask()) & 1)
	r.state = r.state>>1 | feedback<<uint(r.polynomial.Degree-1)
	return output
}

func (r *LFSR) State() string {
	return fmt.Sprintf("%0*b", r.polynomial.Degree, r.state)
}

func (r *LFSR) Period() int { return r.period }

func (r *LFSR) Scrambler() string {
	return fmt.Sprintf("%0*b", r.polynomial.Degree, r.tapMask())
}

func (r *LFSR) tapMask() uint64 {
	return r.polynomial.Mask & ((1 << r.polynomial.Degree) - 1)
}

func (r *LFSR) Reset() { r.state = r.initial }

type SystemConfig struct {
	Register1 RegisterConfig `json:"register1"`
	Register2 RegisterConfig `json:"register2"`
}

func DefaultConfig() SystemConfig {
	return SystemConfig{
		Register1: RegisterConfig{PolynomialRow: 7, Seed: "10101"},
		Register2: RegisterConfig{PolynomialRow: 5, Seed: "1001"},
	}
}

type System struct {
	first       *LFSR
	second      *LFSR
	statePeriod int
	bitPeriod   int
}

func NewSystem(config SystemConfig) (*System, error) {
	first, err := NewLFSR(config.Register1)
	if err != nil {
		return nil, fmt.Errorf("регистр 1: %w", err)
	}
	second, err := NewLFSR(config.Register2)
	if err != nil {
		return nil, fmt.Errorf("регистр 2: %w", err)
	}
	s := &System{first: first, second: second}
	s.statePeriod = first.Period() / gcd(first.Period(), second.Period()) * second.Period()
	// The state period is an upper bound, not proof of the XOR output period.
	// Measure the minimal output period, including equal-register cancellation.
	a, b := *first, *second
	sequence := make([]uint8, s.statePeriod)
	for i := range sequence {
		sequence[i] = a.NextBit() ^ b.NextBit()
	}
	s.bitPeriod = minimalPeriod(sequence)
	return s, nil
}

func (s *System) NextBit() uint8 { return s.first.NextBit() ^ s.second.NextBit() }

func (s *System) NextSymbol() uint8 {
	var symbol uint8
	for i := 0; i < BitsPerSymbol; i++ {
		symbol = symbol<<1 | s.NextBit()
	}
	return symbol
}

func (s *System) BitPeriod() int   { return s.bitPeriod }
func (s *System) StatePeriod() int { return s.statePeriod }
func (s *System) SymbolPeriod() int {
	return s.bitPeriod / gcd(s.bitPeriod, BitsPerSymbol)
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func minimalPeriod(sequence []uint8) int {
	// Prefix function finds the shortest repeated block in linear time.
	prefix := make([]int, len(sequence))
	for i := 1; i < len(sequence); i++ {
		j := prefix[i-1]
		for j > 0 && sequence[i] != sequence[j] {
			j = prefix[j-1]
		}
		if sequence[i] == sequence[j] {
			j++
		}
		prefix[i] = j
	}
	period := len(sequence) - prefix[len(sequence)-1]
	if len(sequence)%period == 0 {
		return period
	}
	return len(sequence)
}
