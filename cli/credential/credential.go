package credential

import (
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger/schema"

	. "github.com/workdaycredentials/credwallet/cli"
	"github.com/workdaycredentials/credwallet/cli/storage/bolt"
)

const (
	credDefIDFlag  = "creddef"
	subjectIDFlag  = "subject"
	credFileFlag   = "cfile"
	attributesFlag = "cjson"
	credIDFlag     = "cid"
)

func init() {
	// Add sub commands to Cred command
	newCred.PersistentFlags().String(credDefIDFlag, "", "Specify the Cred Def ID.")
	newCred.PersistentFlags().String(subjectIDFlag, "", "Specify the Subject (recipient) DID for the Credential..")
	newCred.PersistentFlags().String(credFileFlag, "", "Specify the file with the Credential data.")
	newCred.PersistentFlags().String(attributesFlag, "", "Specify the Credential data in JSON.")
	_ = newCred.MarkFlagRequired(credDefIDFlag)
	_ = newCred.MarkFlagRequired(subjectIDFlag)
	Cred.AddCommand(newCred)

	viewCred.PersistentFlags().String(credIDFlag, "", "Specify the Credential ID.")
	_ = viewCred.MarkFlagRequired(credIDFlag)
	Cred.AddCommand(viewCred)

	// Add Cred command to root and validate
	RootCmd.AddCommand(Cred)
	ValidateFlags(Cred, newCred, viewCred)
}

var (
	Cred = &cobra.Command{
		Use:     "cred",
		Short:   "Work with Credentials",
		Long:    `Generate, view and list Credentials.`,
		Example: "credwallet cred",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			creds, err := storage.ListCredentials()
			if err != nil {
				fmt.Printf("Unable to list Credentials: %s\n", err.Error())
				return CmdErr(cmd, errors.Wrap(err, "unable to list credentials"))
			}

			fmt.Printf("<%d> Credential(s) Found\n", len(creds))
			for _, cred := range creds {
				fmt.Printf("[%s] issued from <%s> to <%s>\n", cred.ID, cred.Issuer, cred.CredentialSubject[credential.SubjectIDAttribute])
			}
			return nil
		},
	}

	newCred = &cobra.Command{
		Use:     "new",
		Short:   "Create a new Cred",
		Long:    "Create a new Cred, and store to the local store.",
		Example: "credwallet cred new --credDef=<id> --subject=<id> --credFile=<filePath>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate flags
			credFile := viper.GetString(credFileFlag)
			credJSON := viper.GetString(attributesFlag)
			if credFile == "" && credJSON == "" {
				errMsg := "could not parse arguments: please specify either cred file or json for credential attributes"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}
			if credFile != "" && credJSON != "" {
				errMsg := "could not parse arguments: please do not specify both cred file and json for cred attributes"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}

			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			// Get the cred def
			credDefID := viper.GetString(credDefIDFlag)
			credDef, err := storage.ReadCredDef(credDefID)
			if err != nil {
				fmt.Printf("Could not get Cred Def with ID: %s, %s\n", credDefID, err.Error())
				return CmdErr(cmd, err)
			}

			// Get the private key of the issuer
			privateKey, err := storage.ReadPrivateKey(credDefID)
			if err != nil {
				fmt.Printf("Could not get private key for Cred Def: %s, %s\n", credDefID, err.Error())
				return CmdErr(cmd, err)
			}

			// Get the subject
			subjectID := viper.GetString(subjectIDFlag)
			if _, err := storage.ReadDIDDoc(subjectID); err != nil {
				fmt.Printf("Unable to resolve subject DID: %s, %s\n", subjectID, err.Error())
				return CmdErr(cmd, err)
			}

			// Read in the credential data
			credData := []byte(credJSON)
			if credFile != "" {
				credData, err = ioutil.ReadFile(credFile)
				credJSON = string(credData)
				if err != nil {
					fmt.Printf("Could not read input file for cred data JSON: %s\n", err.Error())
					return CmdErr(cmd, err)
				}
			}

			// Make sure it's JSON
			if !IsJSON(credData) {
				fmt.Printf("Provided data is not valid JSON: %s\n", credJSON)
				return CmdErr(cmd, err)
			}

			// Get the controller and schemaDoc ID out of the cred def
			info, err := GetCredDefInfo(*credDef)
			if err != nil {
				fmt.Printf("unable to parse cred def: %s, %s\n", credDefID, err.Error())
				return CmdErr(cmd, err)
			}

			// Get the schema doc
			schemaID := info.SchemaID
			schemaDoc, err := storage.ReadSchema(schemaID)
			if err != nil {
				fmt.Printf("Could not get schema with ID: %s, %s\n", schemaID, err.Error())
				return CmdErr(cmd, err)
			}

			// Validate the input json against the schemaDoc
			if err = schema.Validate(schemaDoc.Schema.ToJSON(), credJSON); err != nil {
				fmt.Printf("Credential data did not validate against the schema: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			// Issue the credential
			cred, err := BuildAndSignCredential(credJSON, schemaID, subjectID, *credDef, privateKey)
			if err != nil {
				fmt.Printf("Could not issuer credential: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			// Store cred
			if err := storage.WriteCredential(*cred); err != nil {
				fmt.Printf("Could not store credential: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			// Print it
			StructPrinter(cred)
			return nil
		},
	}

	viewCred = &cobra.Command{
		Use:     "view",
		Short:   "View a Credential",
		Long:    "View a specific Credential",
		Example: "credwallet cred view --cred=<cred-id>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			credID := viper.GetString(credIDFlag)
			cred, err := storage.ReadCredential(credID)
			if err != nil {
				fmt.Printf("Could not read credential with ID: %s, %s\n", credID, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(cred)
			return nil
		},
	}
)
