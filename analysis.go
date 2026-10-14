package gamma

import (
	"fmt"
	"html"
	"math"
	"strings"
)

type Frequency struct {
	Symbol rune
	Count  int
	Share  float64
}

// Histogram always contains the same 32 bins, including absent letters.
func Histogram(text string) ([]Frequency, error) {
	counts := make(map[rune]int)
	for _, letter := range text {
		if !strings.ContainsRune(Alphabet, letter) {
			return nil, fmt.Errorf("неподдерживаемый символ гистограммы %q", letter)
		}
		counts[letter]++
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	histogram := make([]Frequency, 0, 32)
	for _, letter := range Alphabet {
		frequency := Frequency{Symbol: letter, Count: counts[letter]}
		if total > 0 {
			frequency.Share = float64(frequency.Count) / float64(total)
		}
		histogram = append(histogram, frequency)
	}
	return histogram, nil
}

type Statistics struct {
	Length  int
	Entropy float64
	// Distance is the sum of squared distances from the uniform 1/32 distribution.
	Distance float64
}

func Analyze(text string) (Statistics, error) {
	histogram, err := Histogram(text)
	if err != nil {
		return Statistics{}, err
	}
	stats := Statistics{}
	for _, frequency := range histogram {
		stats.Length += frequency.Count
		if frequency.Share > 0 {
			stats.Entropy -= frequency.Share * math.Log2(frequency.Share)
		}
		difference := frequency.Share - 1.0/32
		stats.Distance += difference * difference
	}
	return stats, nil
}

type Sample struct {
	Name string
	Text string
}

// HistogramSVG uses a shared vertical scale for every sample.
func HistogramSVG(samples []Sample) (string, error) {
	if len(samples) == 0 {
		return "", fmt.Errorf("не заданы тексты для анализа")
	}
	histograms := make([][]Frequency, len(samples))
	maximum := 0.0
	for i, sample := range samples {
		var err error
		histograms[i], err = Histogram(sample.Text)
		if err != nil {
			return "", err
		}
		for _, bin := range histograms[i] {
			maximum = math.Max(maximum, bin.Share)
		}
	}
	maximum = math.Max(0.05, math.Ceil(maximum*20)/20)
	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="%d" viewBox="0 0 1200 %d"><rect width="100%%" height="100%%" fill="#fff"/><g font-family="Arial, sans-serif" fill="#18283c">`, len(samples)*330+75, len(samples)*330+75)
	svg.WriteString(`<text x="70" y="35" font-size="23">Гистограммный анализ: частоты символов</text>`)
	colors := []string{"#2563a5", "#159778", "#a36829"}
	for i, sample := range samples {
		top := float64(90 + i*330)
		fmt.Fprintf(&svg, `<text x="70" y="%.0f" font-size="19">%s — %d символов</text>`, top-15, html.EscapeString(sample.Name), len([]rune(sample.Text)))
		for tick := 0; tick <= 4; tick++ {
			value := maximum * float64(tick) / 4
			y := top + 210 - value/maximum*210
			fmt.Fprintf(&svg, `<line x1="70" x2="1150" y1="%.1f" y2="%.1f" stroke="#dce4ed"/><text x="12" y="%.1f" font-size="13">%.1f%%</text>`, y, y, y+4, value*100)
		}
		uniformY := top + 210 - (1.0/32)/maximum*210
		fmt.Fprintf(&svg, `<line x1="70" x2="1150" y1="%.1f" y2="%.1f" stroke="#b13e54" stroke-dasharray="5 4"/>`, uniformY, uniformY)
		for j, bin := range histograms[i] {
			x := 78 + float64(j)*33.5
			height := bin.Share / maximum * 210
			fmt.Fprintf(&svg, `<rect x="%.1f" y="%.1f" width="24" height="%.1f" fill="%s"><title>%c: %d; %.5f</title></rect><text x="%.1f" y="%.1f" text-anchor="middle" font-size="15">%c</text>`, x, top+210-height, height, colors[i%len(colors)], bin.Symbol, bin.Count, bin.Share, x+12, top+232, bin.Symbol)
		}
	}
	fmt.Fprintf(&svg, `<text x="70" y="%d" font-size="14">Пунктир: равномерная частота 1/32 = 3,125%%. Одинаковый масштаб для всех диаграмм.</text></g></svg>`, len(samples)*330+55)
	return svg.String(), nil
}
