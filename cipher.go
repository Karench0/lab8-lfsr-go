package gamma

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	Alphabet      = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
	BitsPerSymbol = 5
	DefaultText   = "Нужна только одна паршивая овца, чтобы испортить все стадо."
	CipherName    = "Шеннон/XOR, система двух РСЛОС"
)

// Normalize prepares laboratory text. Decryption recovers THIS representation;
// removed spaces/case and punctuation substitutions are not automatically undone.
func Normalize(text string) (string, error) {
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("текст должен быть в UTF-8")
	}
	var result strings.Builder
	for _, letter := range strings.ToUpper(text) {
		switch {
		case unicode.IsSpace(letter):
			continue
		case letter == ',':
			result.WriteString("ЗПТ")
		case letter == '.':
			result.WriteString("ТЧК")
		case letter == 'Ё':
			result.WriteRune('Е')
		case strings.ContainsRune(Alphabet, letter):
			result.WriteRune(letter)
		default:
			return "", fmt.Errorf("неподдерживаемый символ %q", letter)
		}
	}
	return result.String(), nil
}

// Crypt applies XOR to five-bit letter indices. Calling it twice with the same
// initial register states returns the input. It never normalizes ciphertext.
func Crypt(text string, config SystemConfig) (string, error) {
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("текст должен быть в UTF-8")
	}
	alphabet := []rune(Alphabet)
	indices := alphabetIndices()
	letters := []rune(text)
	for _, letter := range letters {
		if _, ok := indices[letter]; !ok {
			return "", fmt.Errorf("символ %q отсутствует в алфавите; открытый текст сначала нормализуйте", letter)
		}
	}
	system, err := NewSystem(config)
	if err != nil {
		return "", err
	}
	// Check in bits: the gamma must not wrap even within the last five-bit code.
	if len(letters) > system.BitPeriod()/BitsPerSymbol {
		return "", fmt.Errorf("текст содержит %d символов (%d бит), период гаммы %d бит: выберите более длинные регистры", len(letters), len(letters)*BitsPerSymbol, system.BitPeriod())
	}
	for i, letter := range letters {
		letters[i] = alphabet[indices[letter]^system.NextSymbol()]
	}
	return string(letters), nil
}

type Card struct {
	Version    int          `json:"version"`
	Cipher     string       `json:"cipher"`
	Alphabet   string       `json:"alphabet"`
	Key        SystemConfig `json:"key"`
	Scrambler1 string       `json:"scrambler1"`
	Scrambler2 string       `json:"scrambler2"`
	Ciphertext string       `json:"ciphertext"`
}

func Encrypt(text string, config SystemConfig) (Card, error) {
	plain, err := Normalize(text)
	if err != nil {
		return Card{}, err
	}
	ciphertext, err := Crypt(plain, config)
	if err != nil {
		return Card{}, err
	}
	system, err := NewSystem(config)
	if err != nil {
		return Card{}, err
	}
	return Card{
		Version: 1, Cipher: CipherName, Alphabet: Alphabet, Key: config,
		Scrambler1: system.first.Scrambler(), Scrambler2: system.second.Scrambler(),
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(card Card) (string, error) {
	if card.Version != 1 || card.Cipher != CipherName || card.Alphabet != Alphabet {
		return "", fmt.Errorf("неподдерживаемый формат карточки, шифр или алфавит")
	}
	system, err := NewSystem(card.Key)
	if err != nil {
		return "", err
	}
	if card.Scrambler1 != system.first.Scrambler() || card.Scrambler2 != system.second.Scrambler() {
		return "", fmt.Errorf("скремблеры в карточке не соответствуют многочленам")
	}
	return Crypt(card.Ciphertext, card.Key)
}

func (card Card) JSON() ([]byte, error) { return json.MarshalIndent(card, "", "  ") }

func alphabetIndices() map[rune]uint8 {
	indices := make(map[rune]uint8, 32)
	for i, letter := range []rune(Alphabet) {
		indices[letter] = uint8(i)
	}
	return indices
}
