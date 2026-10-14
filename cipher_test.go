package gamma

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	expectedPlain = "НУЖНАТОЛЬКООДНАПАРШИВАЯОВЦАЗПТЧТОБЫИСПОРТИТЬВСЕСТАДОТЧК"
	// Independently calculated with arrays of cells, rather than integer shifts.
	expectedCipher = "ЛЩЫНЧЗЗРЦАЫРКОСРФЛЕЧЮЕЫЗЖЧЪЯГТЯМЧЧГМПЮЖСАОЗКТЛВЦВЕИЩПАИ"
)

func TestPhraseEncryptionAndDecryption(t *testing.T) {
	card, err := Encrypt(DefaultText, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if card.Ciphertext != expectedCipher {
		t.Fatalf("ciphertext:\n%s\nwant:\n%s", card.Ciphertext, expectedCipher)
	}
	encoded, err := card.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var decodedCard Card
	if err := json.Unmarshal(encoded, &decodedCard); err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(decodedCard)
	if err != nil {
		t.Fatal(err)
	}
	if plain != expectedPlain || len([]rune(plain)) != 55 {
		t.Fatalf("decrypted text: %s", plain)
	}
}

func TestNormalize(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{DefaultText, expectedPlain}, {"Ёж,\n ёлка.\t", "ЕЖЗПТЕЛКАТЧК"}, {" , . ", "ЗПТТЧК"}, {"", ""},
	} {
		got, err := Normalize(test.input)
		if err != nil || got != test.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, text := range []string{"hello", "текст!", "123", string([]byte{0xff})} {
		if _, err := Normalize(text); err == nil {
			t.Errorf("accepted unsupported text %q", text)
		}
	}
}

func TestAllLettersRoundTrip(t *testing.T) {
	for _, text := range []string{Alphabet, "", strings.Repeat("А", 93)} {
		cipher, err := Crypt(text, DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Crypt(cipher, DefaultConfig())
		if err != nil || plain != text {
			t.Fatalf("round trip failed: %q, %v", plain, err)
		}
	}
}

func TestRejectGammaWrapAndInvalidCiphertext(t *testing.T) {
	for _, text := range []string{strings.Repeat("А", 94), "А Б", "А,Б", "abc", string([]byte{0xff})} {
		if _, err := Crypt(text, DefaultConfig()); err == nil {
			t.Errorf("accepted invalid input %q", text)
		}
	}
	same := RegisterConfig{PolynomialRow: 5, Seed: "1001"}
	if _, err := Crypt("А", SystemConfig{same, same}); err == nil {
		t.Fatal("must reject a cancelled gamma with period 1")
	}
}

func TestDifferentKeysAndCardValidation(t *testing.T) {
	config := DefaultConfig()
	config.Register1.Seed = "11001"
	card, err := Encrypt(DefaultText, config)
	if err != nil {
		t.Fatal(err)
	}
	if card.Ciphertext == expectedCipher {
		t.Fatal("different key must change the reference ciphertext")
	}
	plain, err := Decrypt(card)
	if err != nil || plain != expectedPlain {
		t.Fatal("different-key round trip failed")
	}
	for _, change := range []func(*Card){
		func(c *Card) { c.Version = 99 },
		func(c *Card) { c.Cipher = "unknown" },
		func(c *Card) { c.Alphabet = "ABC" },
		func(c *Card) { c.Scrambler1 = "11111" },
		func(c *Card) { c.Key.Register2.Seed = "0000" },
	} {
		invalid := card
		change(&invalid)
		if _, err := Decrypt(invalid); err == nil {
			t.Fatal("accepted an invalid card")
		}
	}
}

func FuzzCipherRoundTrip(f *testing.F) {
	f.Add([]byte{0, 1, 31, 17, 10})
	f.Add([]byte{})
	f.Add([]byte(expectedPlain))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 93 {
			input = input[:93]
		}
		alphabet := []rune(Alphabet)
		letters := make([]rune, len(input))
		for i, value := range input {
			letters[i] = alphabet[value%32]
		}
		text := string(letters)
		cipher, err := Crypt(text, DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		plain, err := Crypt(cipher, DefaultConfig())
		if err != nil || plain != text {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}
