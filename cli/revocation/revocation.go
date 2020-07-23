package revocation

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"

	. "github.com/workdaycredentials/credwallet/cli"
	"github.com/workdaycredentials/credwallet/cli/storage/bolt"
)

const (
	issuerIDFlag     = "issuer"
	credIDFlag       = "cred"
	revocationIDFlag = "revocation"
)

func init() {
	// Add sub commands to Revocation command
	newRevocation.PersistentFlags().String(credIDFlag, "", "Specify the Credential ID.")
	newRevocation.PersistentFlags().String(issuerIDFlag, "", "Specify the Issuer ID.")
	_ = newRevocation.MarkFlagRequired(credIDFlag)
	_ = newRevocation.MarkFlagRequired(issuerIDFlag)
	Revocation.AddCommand(newRevocation)

	viewRevocation.PersistentFlags().String(revocationIDFlag, "", "Specify the Revocation ID.")
	_ = viewRevocation.MarkFlagRequired(revocationIDFlag)
	Revocation.AddCommand(viewRevocation)

	// Add Revocation command to root and validate
	RootCmd.AddCommand(Revocation)
	ValidateFlags(Revocation, newRevocation, viewRevocation)
}

var (
	Revocation = &cobra.Command{
		Use:     "revocation",
		Short:   "Work with Revocations",
		Long:    `Generate, view and list Revocations.`,
		Example: "credwallet revocation",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			revs, err := storage.ListRevocations()
			if err != nil {
				fmt.Printf("Unable to list Revocations: %s\n", err.Error())
				return CmdErr(cmd, errors.Wrap(err, "unable to list revocations"))
			}

			fmt.Printf("<%d> Revocations Found\n", len(revs))
			for _, rev := range revs {
				fmt.Printf("[%s] issued from <%s> about <%s>\n", rev.Metadata.ID, rev.UnsignedRevocation.IssuerDID, rev.UnsignedRevocation.CredentialID)
			}
			return nil
		},
	}

	newRevocation = &cobra.Command{
		Use:     "new",
		Short:   "Create a new Revocation",
		Long:    "Create a new Revocation, and store to the local store.",
		Example: "credwallet revocation new --cred=<id> --issuer=<id>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			credID := viper.GetString(credIDFlag)
			issuerID := viper.GetString(issuerIDFlag)

			// Get issuer DID Doc
			credDef, err := storage.ReadCredDef(issuerID)
			if err != nil {
				fmt.Printf("Could not resolve issuer DID Doc (Cred Def) for ID: %s\n", issuerID)
				return CmdErr(cmd, err)
			}

			// Get key for issuer
			privKey, err := storage.ReadPrivateKey(credDef.ID)
			if err != nil {
				fmt.Printf("Could not resolve issuer private key for ID: %s\n", issuerID)
				return CmdErr(cmd, err)
			}

			// Build signer
			keyRef := credDef.PublicKey[0].ID
			signer, err := proof.NewEd25519Signer(privKey, keyRef)
			if err != nil {
				return err
			}

			// Create revocation
			revocation, err := ledger.GenerateLedgerRevocation(credID, issuerID, signer, proof.JCSEdSignatureType)
			if err != nil {
				fmt.Printf("Could not generate revocation: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			// Store revocation
			if err := storage.WriteRevocation(*revocation); err != nil {
				fmt.Printf("Could not storage revocation: %s\n", err.Error())
				return CmdErr(cmd, err)
			}

			// Print it
			StructPrinter(revocation)
			return nil
		},
	}

	viewRevocation = &cobra.Command{
		Use:     "view",
		Short:   "View a Revocation",
		Long:    "View a specific Revocation",
		Example: "credwallet cred view --revocation=<revocation-id>",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			revID := viper.GetString(revocationIDFlag)
			revocation, err := storage.ReadRevocation(revID)
			if err != nil {
				fmt.Printf("Could not read Revocation with ID: %s, %s\n", revID, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(revocation)
			return nil
		},
	}
)
