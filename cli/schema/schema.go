package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/workdaycredentials/ledger-common/ledger"

	. "github.com/workdaycredentials/credwallet/cli"

	"github.com/workdaycredentials/credwallet/cli/storage/bolt"
)

const (
	attributesFlag = "schemaJson"
	authorFlag     = "schemaAuthor"
	schemaFileFlag = "schemaFile"
	schemaIDFlag   = "schemaId"
)

func init() {
	newSchema.PersistentFlags().String(schemaFileFlag, "", "Can be used to specify attributes in JSON format in an input file")
	newSchema.PersistentFlags().String(attributesFlag, "", "Can be used to specify attributes in JSON format")
	newSchema.PersistentFlags().String(authorFlag, "", "Can be used to specify the author DID for signing the schema")
	_ = newSchema.MarkFlagRequired(authorFlag)
	Schema.AddCommand(newSchema)

	viewSchema.PersistentFlags().String(schemaIDFlag, "", "Can be used to specify the ID of the schema")
	_ = viewSchema.MarkFlagRequired(schemaIDFlag)
	Schema.AddCommand(viewSchema)

	RootCmd.AddCommand(Schema)
	ValidateFlags(Schema, newSchema, viewSchema)
}

var (
	Schema = &cobra.Command{
		Use:     "schema",
		Short:   "Work with Schemas",
		Long:    `Generate, view and list Schemas. Stores schemas to the key-store.`,
		Example: "credwallet schema",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()
			schemas, err := storage.ListSchemas()
			if err != nil {
				fmt.Printf("Unable to read Schemas: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			fmt.Printf("<%d> Schemas Found\n", len(schemas))
			for _, schema := range schemas {
				fmt.Println(schema.ID)
			}
			return nil
		},
	}

	newSchema = &cobra.Command{
		Use:     "new",
		Short:   "create new schema",
		Long:    "Create a new schema, and store to the local store.",
		Example: fmt.Sprintf("credwallet schema generate --%s=</input/sample-schema.json> --%s=<schema-author>,", schemaFileFlag, authorFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate flags
			schemaFile := viper.GetString(schemaFileFlag)
			schemaJSON := viper.GetString(attributesFlag)
			if schemaFile == "" && schemaJSON == "" {
				errMsg := "could not parse arguments: please specify either schema file or json for schema attributes"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}
			if schemaFile != "" && schemaJSON != "" {
				errMsg := "could not parse arguments: please do not specify both schema file and json for schema attributes"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}
			author := viper.GetString(authorFlag)
			if author == "" {
				errMsg := "could not parse argument: schema author"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}
			inputData := []byte(schemaJSON)
			var err error
			if schemaFile != "" {
				// Read schema input from file
				inputData, err = ioutil.ReadFile(schemaFile)
				if err != nil {
					fmt.Printf("Could not read input file for schema JSON: %s\n", err.Error())
					return CmdErr(cmd, err)
				}
			}

			var schemaInput ledger.JSONSchemaMap
			if err = json.Unmarshal(inputData, &schemaInput); err != nil {
				return CmdErr(cmd, err)
			}

			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initialize local store: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			privateKey, err := storage.ReadPrivateKey(author)
			if err != nil {
				fmt.Printf("Unable to retrieve and parse private key from store: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			authorDoc, err := storage.ReadDIDDoc(author)
			if err != nil {
				fmt.Printf("Unable to read author DID Doc: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			schema, err := BuildAndSignSchema(schemaInput, privateKey, *authorDoc)
			if err != nil {
				return CmdErr(cmd, err)
			}

			if err = storage.WriteSchema(*schema); err != nil {
				fmt.Printf("Unable to write Schema <%s> to storage: %s\n", schema.ID, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(schema)
			return nil
		},
	}

	viewSchema = &cobra.Command{
		Use:     "view",
		Short:   "view schema",
		Long:    "View a schema, using its ID.",
		Example: fmt.Sprintf("credwallet schema view --%s=<schema-id>", schemaIDFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			id := viper.GetString(schemaIDFlag)
			schema, err := storage.ReadSchema(id)
			if err != nil {
				fmt.Printf("Unable to read Schema<%s>: %s\n", id, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(schema)
			return nil
		},
	}
)
