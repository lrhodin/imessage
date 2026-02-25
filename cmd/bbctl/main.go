package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/beeper/bridge-manager/api/hungryapi"
)

const baseDomain = "beeper.com"

type contextKey int

const (
	contextKeyConfig contextKey = iota
	contextKeyEnvConfig
	contextKeyHungryClient
)

func getConfig(ctx *cli.Context) *Config {
	return ctx.Context.Value(contextKeyConfig).(*Config)
}

func getEnvConfig(ctx *cli.Context) *EnvConfig {
	return ctx.Context.Value(contextKeyEnvConfig).(*EnvConfig)
}

func getHungryClient(ctx *cli.Context) *hungryapi.Client {
	val := ctx.Context.Value(contextKeyHungryClient)
	if val == nil {
		return nil
	}
	return val.(*hungryapi.Client)
}

func getConfigPath() string {
	baseDir, _ := os.UserConfigDir()
	return filepath.Join(baseDir, "bbctl", "config.json")
}

func prepareApp(ctx *cli.Context) error {
	cfg, err := loadConfig(ctx.String("config"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	envCfg := cfg.Environments.Get("prod")
	newCtx := context.WithValue(ctx.Context, contextKeyConfig, cfg)
	newCtx = context.WithValue(newCtx, contextKeyEnvConfig, envCfg)
	if envCfg.HasCredentials() {
		hungryClient := hungryapi.NewClient(baseDomain, envCfg.Username, envCfg.AccessToken)
		newCtx = context.WithValue(newCtx, contextKeyHungryClient, hungryClient)
	}
	ctx.Context = newCtx
	return nil
}

func requiresAuth(ctx *cli.Context) error {
	if err := prepareApp(ctx); err != nil {
		return err
	}
	if !getEnvConfig(ctx).HasCredentials() {
		return fmt.Errorf("you are not logged in — run 'bbctl login' first")
	}
	return nil
}

func main() {
	app := &cli.App{
		Name:    "bbctl",
		Usage:   "Manage self-hosted Beeper bridges",
		Version: "0.1.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Path to config file",
				Value: getConfigPath(),
			},
		},
		Commands: []*cli.Command{
			loginCommand,
			logoutCommand,
			whoamiCommand,
			configCommand,
			deleteCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
