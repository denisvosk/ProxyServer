package cli

import (
	"fmt"

	"github.com/9seconds/mtg/v2/internal/utils"
)

type Run struct {
	ConfigPath        string `kong:"arg,required,help='Path to the configuration file, or - for stdin.',name='config-path'"` //nolint: lll
	SkipStartupChecks bool   `kong:"name='skip-startup-checks',help='Skip optional public-IP/SNI startup diagnostics.'"`
}

func (r *Run) Run(cli *CLI, version string) error {
	conf, err := utils.ReadConfig(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot init config: %w", err)
	}

	return runProxy(conf, version, r.SkipStartupChecks)
}
