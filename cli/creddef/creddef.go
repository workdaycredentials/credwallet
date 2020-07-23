package creddef

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	. "github.com/workdaycredentials/credwallet/cli"
	"github.com/workdaycredentials/credwallet/cli/storage/bolt"

	"encoding/hex"
)

const (
	idFlag         = "cdid"
	controllerFlag = "controller"
	schemaIDFlag   = "schema"
)

func init() {
	newCredDef.PersistentFlags().String(controllerFlag, "", "Specify the DID to be the controller of the Cred Def.")
	newCredDef.PersistentFlags().String(schemaIDFlag, "", "Specify the Schema to use in the Cred Def.")
	_ = newCredDef.MarkFlagRequired(controllerFlag)
	_ = newCredDef.MarkFlagRequired(schemaIDFlag)
	CredDef.AddCommand(newCredDef)

	viewCredDef.PersistentFlags().String(idFlag, "", "Specify the Cred Def ID.")
	_ = viewCredDef.MarkFlagRequired(idFlag)
	CredDef.AddCommand(viewCredDef)

	RootCmd.AddCommand(CredDef)
	ValidateFlags(CredDef, newCredDef, viewCredDef)
}

var (
	CredDef = &cobra.Command{
		Use:     "creddef",
		Short:   "Work with Credential Definitions",
		Long:    `Generate, view and list Credential Definitions: the binding of a schema to an identity as a new identity.`,
		Example: "credwallet creddef",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			credDef, err := storage.ListCredDefs()
			if err != nil {
				fmt.Printf("Unable to list Cred Defs: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			fmt.Printf("<%d> Cred Def(s) Found\n", len(credDef))
			for _, doc := range credDef {
				fmt.Printf("%s - Schema: %s\n", doc.ID, doc.Service[0].ID)
			}
			return nil
		},
	}

	newCredDef = &cobra.Command{
		Use:     "new",
		Short:   "Create a new Cred Def DID",
		Long:    "Create a new Cred Def DID, and store key-material to the local store.",
		Example: "credwallet creddef new --controller=<id> --schema=<id>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			controllerDID := viper.GetString(controllerFlag)
			schemaID := viper.GetString(schemaIDFlag)

			// Build the cred def
			credDef, privateKey, err := BuildCredDef(controllerDID, schemaID)
			if err != nil {
				fmt.Printf("Could not build cred def: %s", err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(credDef)
			fmt.Printf("Private Key (hex): %s\n", hex.EncodeToString(privateKey))

			if err := storage.WriteCredDef(*credDef, controllerDID, schemaID); err != nil {
				fmt.Printf("Unable to write DID Doc<%s> to storage: %s\n", credDef.ID, err.Error())
				return CmdErr(cmd, err)
			}
			if err := storage.WritePrivateKey(credDef.ID, privateKey); err != nil {
				fmt.Printf("Unable to write private key for Cred Def<%s> to storage: %s", credDef.ID, err.Error())
				return CmdErr(cmd, err)
			}
			return nil
		},
	}

	viewCredDef = &cobra.Command{
		Use:     "view",
		Short:   "View a DID Document",
		Long:    "View a specific DID Document",
		Example: "credwallet did view --id=<id>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			id := viper.GetString(idFlag)
			credDef, err := storage.ReadCredDef(id)
			if err != nil {
				fmt.Printf("Unable to read Cred Def<%s>: %s\n", id, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(credDef)
			return nil
		},
	}
)
