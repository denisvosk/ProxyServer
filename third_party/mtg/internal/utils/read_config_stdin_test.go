package utils_test

import (
	"os"
	"strings"
	"testing"

	"github.com/9seconds/mtg/v2/internal/utils"
)

// Desktop integration regression: credentials arrive through an inherited pipe,
// not a command line or a persistent configuration file. Test data is synthetic.
func TestReadConfigFromStdin(t *testing.T) {
	valid := "secret = \"ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d\"\n" +
		"bind-to = \"127.0.0.1:12345\"\n"
	for _, tc := range []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid", valid, false},
		{"invalid", "not valid TOML", true},
		{"oversize", valid + strings.Repeat("#", 64*1024), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "stdin-config-")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			previous := os.Stdin
			os.Stdin = f
			defer func() { os.Stdin = previous }()
			conf, err := utils.ReadConfig("-")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error = %v", err, tc.wantErr)
			}
			if !tc.wantErr && conf.Secret.Host != "example.com" {
				t.Fatalf("unexpected secret hostname")
			}
		})
	}
}
