package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gamma "github.com/Karench0/lab8-lfsr-go"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

type paths []string

func (p *paths) String() string { return strings.Join(*p, ", ") }
func (p *paths) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func run(args []string, stdout, stderr io.Writer) error {
	command := "demo"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}
	if command == "help" || command == "-h" || command == "--help" {
		_, err := fmt.Fprintln(stdout, "ЛР8: demo | encrypt | decrypt\nПримеры:\n  lab8 demo -out results\n  lab8 encrypt -text \"Нужна только одна паршивая овца, чтобы испортить все стадо.\" -out card.json\n  lab8 decrypt -in card.json\nПараметры шифрования: -poly1 7 -key1 10101 -poly2 5 -key2 1001\nДля сравнения: demo -compare other-cipher.txt (флаг можно повторять)")
		return err
	}
	if command != "demo" && command != "encrypt" && command != "decrypt" {
		return fmt.Errorf("неизвестная команда %q; используйте help", command)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("in", "", "UTF-8 файл: открытый текст или JSON-карточка для decrypt")
	output := flags.String("out", "", "каталог отчёта для demo, файл для encrypt/decrypt")
	text := flags.String("text", gamma.DefaultText, "открытый текст")
	config := gamma.DefaultConfig()
	flags.IntVar(&config.Register1.PolynomialRow, "poly1", config.Register1.PolynomialRow, "номер многочлена из таблицы П1.1 для регистра 1")
	flags.IntVar(&config.Register2.PolynomialRow, "poly2", config.Register2.PolynomialRow, "номер многочлена из таблицы П1.1 для регистра 2")
	flags.StringVar(&config.Register1.Seed, "key1", config.Register1.Seed, "начальные биты регистра 1")
	flags.StringVar(&config.Register2.Seed, "key2", config.Register2.Seed, "начальные биты регистра 2")
	var compare paths
	flags.Var(&compare, "compare", "файл дополнительного шифртекста в алфавите из 32 букв")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("лишние аргументы: %s", strings.Join(flags.Args(), " "))
	}
	if command != "demo" && len(compare) > 0 {
		return fmt.Errorf("-compare доступен только для demo")
	}
	if command == "decrypt" {
		if *input == "" {
			return fmt.Errorf("укажите -in card.json")
		}
		file, err := os.Open(*input)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		var card gamma.Card
		err = decoder.Decode(&card)
		if err == nil {
			var trailing any
			if tailErr := decoder.Decode(&trailing); tailErr != io.EOF {
				err = fmt.Errorf("карточка должна содержать ровно один JSON-объект")
			}
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		plain, err := gamma.Decrypt(card)
		if err != nil {
			return err
		}
		return writeResult(*output, []byte(plain+"\n"), stdout)
	}
	if *input != "" {
		contents, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		*text = string(contents)
	}
	if command == "encrypt" {
		card, err := gamma.Encrypt(*text, config)
		if err != nil {
			return err
		}
		contents, err := card.JSON()
		if err != nil {
			return err
		}
		return writeResult(*output, append(contents, '\n'), stdout)
	}
	extra := make([]gamma.Sample, 0, len(compare))
	for _, path := range compare {
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Only trim a file's trailing whitespace; never substitute punctuation in ciphertext.
		extra = append(extra, gamma.Sample{Name: filepath.Base(path), Text: strings.TrimSpace(string(contents))})
	}
	if *output == "" {
		*output = "results"
	}
	if err := gamma.WriteReport(*output, *text, config, extra); err != nil {
		return err
	}
	card, err := gamma.Encrypt(*text, config)
	if err != nil {
		return err
	}
	plain, err := gamma.Decrypt(card)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Шифртекст: %s\nРасшифрование: %s\nОтчёт: %s\n", card.Ciphertext, plain, filepath.Join(*output, "report.md"))
	return err
}

func writeResult(path string, contents []byte, stdout io.Writer) error {
	if path == "" {
		_, err := stdout.Write(contents)
		return err
	}
	return os.WriteFile(path, contents, 0644)
}
