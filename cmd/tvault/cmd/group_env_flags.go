package cmd

import "fmt"

func validateGroupEnvFlags(group, env string) error {
	if (group == "") != (env == "") {
		return fmt.Errorf("--group and --env must be used together")
	}
	return nil
}
