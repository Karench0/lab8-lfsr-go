package gamma

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WriteReport builds a reproducible laboratory report, without embedding the PDFs.
func WriteReport(directory, text string, config SystemConfig, extra []Sample) error {
	card, err := Encrypt(text, config)
	if err != nil {
		return err
	}
	plain, err := Normalize(text)
	if err != nil {
		return err
	}
	decoded, err := Decrypt(card)
	if err != nil {
		return err
	}
	if decoded != plain {
		return fmt.Errorf("контрольное расшифрование не совпало с открытым текстом")
	}
	system, err := NewSystem(config)
	if err != nil {
		return err
	}
	samples := append([]Sample{{"Открытый текст", plain}, {"Шифртекст РСЛОС", card.Ciphertext}}, extra...)
	svg, err := HistogramSVG(samples)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	jsonCard, err := card.JSON()
	if err != nil {
		return err
	}
	files := map[string]string{
		"card.json":      string(jsonCard) + "\n",
		"plaintext.txt":  plain + "\n",
		"ciphertext.txt": card.Ciphertext + "\n",
		"decrypted.txt":  decoded + "\n",
		"histograms.svg": svg,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0644); err != nil {
			return err
		}
	}
	if err := writeRegisterTrace(filepath.Join(directory, "register1.csv"), system.first); err != nil {
		return err
	}
	if err := writeRegisterTrace(filepath.Join(directory, "register2.csv"), system.second); err != nil {
		return err
	}
	if err := writeSystemTrace(filepath.Join(directory, "system.csv"), config); err != nil {
		return err
	}
	if err := writeEncryptionTrace(filepath.Join(directory, "encryption.csv"), plain, config); err != nil {
		return err
	}
	if err := writeFrequencies(filepath.Join(directory, "frequencies.csv"), samples); err != nil {
		return err
	}
	// Variant 1, task 1 is a distinct four-bit register with period 15.
	exercise, err := NewLFSR(RegisterConfig{PolynomialRow: 5, Seed: "1001"})
	if err != nil {
		return err
	}
	if err := writeRegisterTrace(filepath.Join(directory, "task1-variant1.csv"), exercise); err != nil {
		return err
	}
	// Follow task 2's two-four-bit construction, while reporting its real period.
	exerciseSystem := SystemConfig{RegisterConfig{5, "1001"}, RegisterConfig{5, "0101"}}
	if err := writeSystemTrace(filepath.Join(directory, "task2-variant1.csv"), exerciseSystem); err != nil {
		return err
	}
	return writeReportMarkdown(filepath.Join(directory, "report.md"), text, plain, card, system, samples)
}

func writeCSV(path string, rows [][]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	writer.WriteAll(rows)
	writeErr := writer.Error()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeRegisterTrace(path string, register *LFSR) error {
	probe := *register
	probe.Reset()
	rows := [][]string{{"step", "state_before_shift", "output_bit"}}
	for step := 1; step <= probe.Period()+1; step++ {
		state := probe.State()
		bit := probe.NextBit()
		rows = append(rows, []string{strconv.Itoa(step), state, strconv.Itoa(int(bit))})
	}
	return writeCSV(path, rows)
}

func writeSystemTrace(path string, config SystemConfig) error {
	system, err := NewSystem(config)
	if err != nil {
		return err
	}
	rows := [][]string{{"step", "register1_before_shift", "register2_before_shift", "output1", "output2", "gamma_bit"}}
	for step := 1; step <= system.StatePeriod()+1; step++ {
		state1, state2 := system.first.State(), system.second.State()
		bit1, bit2 := system.first.NextBit(), system.second.NextBit()
		rows = append(rows, []string{strconv.Itoa(step), state1, state2, strconv.Itoa(int(bit1)), strconv.Itoa(int(bit2)), strconv.Itoa(int(bit1 ^ bit2))})
	}
	return writeCSV(path, rows)
}

func writeEncryptionTrace(path, plain string, config SystemConfig) error {
	system, err := NewSystem(config)
	if err != nil {
		return err
	}
	alphabet := []rune(Alphabet)
	indices := alphabetIndices()
	rows := [][]string{{"position", "plain_letter", "plain_index", "plain_bits", "gamma_bits", "gamma_index", "cipher_bits", "cipher_letter"}}
	for position, letter := range []rune(plain) {
		index := indices[letter]
		gamma := system.NextSymbol()
		cipher := uint8(index) ^ gamma
		rows = append(rows, []string{strconv.Itoa(position + 1), string(letter), strconv.Itoa(int(index)), fmt.Sprintf("%05b", index), fmt.Sprintf("%05b", gamma), strconv.Itoa(int(gamma)), fmt.Sprintf("%05b", cipher), string(alphabet[cipher])})
	}
	return writeCSV(path, rows)
}

func writeFrequencies(path string, samples []Sample) error {
	rows := [][]string{{"sample", "symbol", "count", "total", "frequency"}}
	for _, sample := range samples {
		histogram, err := Histogram(sample.Text)
		if err != nil {
			return err
		}
		for _, bin := range histogram {
			rows = append(rows, []string{sample.Name, string(bin.Symbol), strconv.Itoa(bin.Count), strconv.Itoa(len([]rune(sample.Text))), strconv.FormatFloat(bin.Share, 'f', 8, 64)})
		}
	}
	return writeCSV(path, rows)
}

func writeReportMarkdown(path, original, plain string, card Card, system *System, samples []Sample) error {
	var report strings.Builder
	report.WriteString("# Лабораторная работа 8. Гаммирование на системе РСЛОС\n\n")
	report.WriteString("Вариант 1 принят по уточнению пользователя. Текст задан пользователем; файл вариантов из Moodle не использовался, так как ссылка недоступна.\n\n")
	fmt.Fprintf(&report, "## Текст и кодирование\n\nИсходная фраза: %s\n\nПодготовленный текст:\n\n```text\n%s\n```\n\n", original, plain)
	fmt.Fprintf(&report, "Алфавит: `%s`. Индексы 0–31 кодируются пятью битами, старший бит идёт первым. `Ё → Е`, `, → ЗПТ`, `. → ТЧК`; пробелы удаляются. Получено %d символов, %d бит. Расшифрование восстанавливает подготовленный текст.\n\n", Alphabet, len([]rune(plain)), len([]rune(plain))*BitsPerSymbol)
	report.WriteString("## Задание 1, вариант 1\n\nТаблица 3 задаёт период 15. Выбран многочлен №5 таблицы П1.1: `x^4+x+1`, скремблер `0011`, начальный ключ `1001`. Обратная связь: `q2 XOR q1`. Период проверен перебором: 15; полная таблица с повторным начальным состоянием — `task1-variant1.csv`.\n\n")
	report.WriteString("## Задание 2: противоречие в условии\n\nВ таблице 3 для варианта 1 указано 38. Если к четырёхбитному регистру задания 1 добавить ещё один четырёхбитный РСЛОС, как требует текст задания, точный период 38 получить нельзя. У каждого ненулевого регистра не более 15 состояний; период совместного состояния при синхронных сдвигах равен НОК индивидуальных периодов. Чтобы он делился на 19, один из индивидуальных периодов должен делиться на 19, что невозможно. Период XOR-выхода делит период совместного состояния, поэтому тоже не может быть 38.\n\nДля шифрования фразы ниже реализована система по схеме задания 2 с длинами 5 и 4 бита и достаточным периодом. Она не выдаётся за систему с точным периодом 38.\n\n")
	report.WriteString("Построение с требуемыми длинами 4+4: оба многочлена `x^4+x+1`, скремблеры `0011/0011`, ключи `1001/0101`. Фактический период состояния и XOR-выхода — 15; таблица `task2-variant1.csv`. Для шифрования фразы эта короткая система не применяется.\n\n")
	report.WriteString("## Генератор для шифрования фразы\n\n| Параметр | Регистр 1 | Регистр 2 |\n|---|---|---|\n")
	fmt.Fprintf(&report, "| Строка таблицы П1.1 | %d | %d |\n| Многочлен | %s | %s |\n| Длина | %d | %d |\n| Скремблер | `%s` | `%s` |\n| Начальный ключ | `%s` | `%s` |\n| Проверенный период | %d | %d |\n\n", system.first.polynomial.Row, system.second.polynomial.Row, system.first.polynomial.Name, system.second.polynomial.Name, system.first.polynomial.Degree, system.second.polynomial.Degree, card.Scrambler1, card.Scrambler2, card.Key.Register1.Seed, card.Key.Register2.Seed, system.first.Period(), system.second.Period())
	report.WriteString("Клетки нумеруются справа налево от 1 до m. Состояние записывается от q_m до q_1. Выходной бит снимается с q_1 до сдвига вправо. Для многочлена `p(x)=x^m+Σ a_i x^i` применяется рекуррентное соотношение `b(t+m)=XOR a_i b(t+i)`, где i=0…m−1. Поэтому коэффициент x^i соответствует клетке q_(i+1), а старший член x^m не включается в маску отводов. Единицы скремблера показывают физические клетки для XOR; результат входит в q_m.\n\nЭто явная конвенция расположения отводов: запись коэффициентов без свободного члена из текста PDF не следует автоматически использовать как битовую маску при сдвиге вправо. Пример PDF со скремблером 101 и ключом 110 точно воспроизводится; в данной конвенции ему соответствует `x^3+x^2+1` (№4).\n\n")
	fmt.Fprintf(&report, "Период совместного состояния: НОК(%d, %d) = %d. Минимальный период выходной битовой гаммы отдельно проверен по всему циклу: %d. Период последовательности пятибитных величин: P / НОД(P, 5) = %d. Требуется %d бит, поэтому гамма не успевает повториться.\n\n", system.first.Period(), system.second.Period(), system.StatePeriod(), system.BitPeriod(), system.SymbolPeriod(), len([]rune(plain))*BitsPerSymbol)
	report.WriteString("```mermaid\nflowchart LR\n    A[РСЛОС 1: выход q1] --> X((XOR))\n    B[РСЛОС 2: выход q1] --> X\n    X --> G[5 бит гаммы]\n    P[5 бит буквы] --> C((XOR))\n    G --> C\n    C --> T[Буква шифртекста]\n```\n\n")
	report.WriteString("Шифрование: `c_i = m_i XOR gamma_i`. Расшифрование: `m_i = c_i XOR gamma_i`. При расшифровании регистры запускаются заново с исходными ключами. Таблицы: `register1.csv`, `register2.csv`, `system.csv`; вычисления по каждой букве — `encryption.csv`.\n\n")
	fmt.Fprintf(&report, "## Карточка\n\nШифр: %s.\n\nКлюч: скремблеры `%s / %s`; начальные состояния `%s / %s`.\n\nШифровка:\n\n```text\n%s\n```\n\nКарточка с параметрами для расшифрования: `card.json`.\n\n", CipherName, card.Scrambler1, card.Scrambler2, card.Key.Register1.Seed, card.Key.Register2.Seed, card.Ciphertext)
	report.WriteString("## Гистограммный анализ\n\nЧастота символа: `p_i = count_i / N`. Учитываются все 32 буквы, включая отсутствующие. Во всех диаграммах одна шкала; значения и количества приведены в `frequencies.csv`.\n\n![Гистограммы](histograms.svg)\n\n| Текст | N | Энтропия, бит/символ | Σ(p_i−1/32)² |\n|---|---:|---:|---:|\n")
	bestIndex := 1
	bestDistance := 0.0
	for i, sample := range samples {
		stats, err := Analyze(sample.Text)
		if err != nil {
			return err
		}
		fmt.Fprintf(&report, "| %s | %d | %.6f | %.6f |\n", strings.ReplaceAll(sample.Name, "|", "/"), stats.Length, stats.Entropy, stats.Distance)
		if i >= 1 && (i == 1 || stats.Distance < bestDistance) {
			bestIndex, bestDistance = i, stats.Distance
		}
	}
	plainStats, _ := Analyze(plain)
	for _, sample := range samples[1:] {
		stats, _ := Analyze(sample.Text)
		relation := "ровнее"
		if stats.Distance > plainStats.Distance {
			relation = "менее ровная"
		} else if stats.Distance == plainStats.Distance {
			relation = "такая же по выбранной мере ровности"
		}
		fmt.Fprintf(&report, "\nПара «открытый текст — %s»: диаграмма шифртекста %s (%.6f против %.6f).\n", sample.Name, relation, stats.Distance, plainStats.Distance)
	}
	fmt.Fprintf(&report, "\nНаиболее ровная диаграмма **среди предоставленных шифртекстов**: %s; критерий — минимальная сумма квадратов отклонений от 1/32.\n", samples[bestIndex].Name)
	if len(samples) == 2 {
		report.WriteString("\nДругие шифртексты и файл «Пример гистограммного анализа» не предоставлены. Поэтому вывод о лучшем шифре всего курса сделать нельзя. Дополнительные шифртексты можно добавить через повторяемый флаг `demo -compare file.txt`.\n")
	}
	report.WriteString("\n## Выводы\n\nСистема генерирует достаточную для фразы гамму; контрольное расшифрование совпало с подготовленным текстом. Перебор подтверждает периоды обоих регистров и отдельно XOR-выхода. На коротком тексте гистограмма не обязана быть равномерной: частотный анализ описывает данный образец, но не доказывает стойкость шифра.\n\nЭто учебное гаммирование с детерминированными РСЛОС, а не совершенный одноразовый блокнот Шеннона со случайным одноразовым ключом. Система из двух линейных регистров с XOR остаётся линейной. Начальные ключи в карточке опубликованы для воспроизводимости лабораторной работы.\n")
	return os.WriteFile(path, []byte(report.String()), 0644)
}
