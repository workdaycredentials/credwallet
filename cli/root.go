package cli

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/text"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.credwallet.yaml)")
	ValidateFlags(RootCmd)
}

var cfgFile string

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".credwallet")
	}
	viper.SetEnvPrefix("credwallet")
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

var RootCmd = &cobra.Command{
	Use:           "credwallet",
	Short:         "credwallet is a command line wallet for Workday Credentials.",
	Long:          `credwallet is a command line wallet to demonstrate the protocols that Workday Credentials is built on.`,
	SilenceErrors: true,
	SilenceUsage:  true,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.UsageString())
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		RootCmd.Println(text.FgHiRed.Sprintf("Error: %+v", err))
		os.Exit(1)
	}
}
