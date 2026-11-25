package utils

import (
	"fmt"
	"io"
	"os"

	"github.com/9seconds/mtg/v2/internal/config"
)

func ReadConfig(path string) (*config.Config, error) {
	var content []byte
	var err error
	if path == "-" {
		const maxStdinConfig = 64 * 1024
		content, err = io.ReadAll(io.LimitReader(os.Stdin, maxStdinConfig+1))
		if len(content) > maxStdinConfig {
			return nil, fmt.Errorf("stdin config exceeds 64 KiB")
		}
	} else {
		content, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	conf, err := config.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}

	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}
