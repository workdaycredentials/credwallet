package did

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/workdaycredentials/ledger-common/ledger"

	"github.com/workdaycredentials/ledger-common/proof"

	. "github.com/workdaycredentials/credwallet/cli"
	"github.com/workdaycredentials/credwallet/cli/storage/bolt"
)

const (
	didFlag = "did"
)

func init() {
	// Add sub commands to DID command
	DID.AddCommand(newDID)

	viewDID.PersistentFlags().String(didFlag, "", "Specify the DID doc id.")
	_ = viewDID.MarkFlagRequired(didFlag)
	DID.AddCommand(viewDID)

	// Add DID command to root and validate
	RootCmd.AddCommand(DID)
	ValidateFlags(DID, viewDID, newDID)
}

var (
	DID = &cobra.Command{
		Use:     "did",
		Short:   "Work with DIDs",
		Long:    `Generate, view and list DIDs. Stores key material to the key-store.`,
		Example: "credwallet did",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			docs, err := storage.ListDIDs()
			if err != nil {
				fmt.Printf("Unable to list DIDs: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			fmt.Printf("<%d> DID Docs Found\n", len(docs))
			for _, doc := range docs {
				fmt.Println(doc.ID)
			}
			return nil
		},
	}

	newDID = &cobra.Command{
		Use:     "new",
		Short:   "Create a new DID",
		Long:    "Create a new DID, and store key-material to the local store.",
		Example: "credwallet did new",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			didDoc, privateKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
			StructPrinter(KeyMaterial{DIDDoc: *didDoc, PrivateKey: hex.EncodeToString(privateKey)})

			if err := storage.WriteDID(*didDoc); err != nil {
				fmt.Printf("Unable to write DID Doc<%s> to storage: %s\n", didDoc.ID, err.Error())
				return CmdErr(cmd, err)
			}
			if err := storage.WritePrivateKey(didDoc.ID, privateKey); err != nil {
				fmt.Printf("Unable to write private key for DID Doc<%s> to storage: %s\n", didDoc.ID, err.Error())
				return CmdErr(cmd, err)
			}
			return nil
		},
	}

	viewDID = &cobra.Command{
		Use:     "view",
		Short:   "View a DID Document",
		Long:    "View a specific DID Document",
		Example: fmt.Sprintf("credwallet did view --%s=<did>", didFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			id := viper.GetString(didFlag)
			doc, err := storage.ReadDIDDoc(id)
			if err != nil {
				fmt.Printf("Unable to read DID<%s>: %s\n", id, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(doc)
			return nil
		},
	}
)

