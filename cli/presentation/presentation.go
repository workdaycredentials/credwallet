package presentation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	. "github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/ledger"

	. "github.com/workdaycredentials/credwallet/cli"
	"github.com/workdaycredentials/credwallet/cli/storage/bolt"
)

const (
	inputFileFlag             = "presFile"
	inputJSONFlag             = "presJson"
	presentationRequestIDFlag = "presId"
	presentationHolderIDFlag  = "presHolder"

	viewPresReqIDFlag  = "presReqId"
	viewPresRespIDFlag = "presRespId"
)

func init() {
	// Add sub commands to Presentation command
	newPresentationRequest.PersistentFlags().String(inputFileFlag, "", "Specify the presentation request in JSON format in the input file.")
	newPresentationRequest.PersistentFlags().String(inputJSONFlag, "", "Specify the presentation request in JSON format.")
	Pres.AddCommand(newPresentationRequest)

	newPresentationResponse.PersistentFlags().String(presentationHolderIDFlag, "", "Specify the DID of the presentation subject")
	newPresentationResponse.PersistentFlags().String(presentationRequestIDFlag, "", "Specify the ID of the presentation request")
	Pres.AddCommand(newPresentationResponse)

	// Add view commands
	viewPresentationRequest.PersistentFlags().String(viewPresReqIDFlag, "", "Specify the ID of the presentation request")
	viewPresentationResponse.PersistentFlags().String(viewPresRespIDFlag, "", "Specify the ID of the presentation response")
	Pres.AddCommand(viewPresentationRequest, viewPresentationResponse)

	// Add Presentation command to root and validate
	RootCmd.AddCommand(Pres)
	ValidateFlags(Pres, newPresentationRequest, newPresentationResponse, viewPresentationRequest, viewPresentationResponse)
}

var (
	Pres = &cobra.Command{
		Use:     "presentation",
		Short:   "Generate, respond to, and verify presentation requests",
		Long:    `Generate, respond to, and verify presentation requests. Stores data to the key-store.`,
		Example: "credwallet presentation",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return err
			}
			defer storage.Close()

			requests, err := storage.ListPresentationRequests()
			if err != nil {
				fmt.Printf("Unable to read Presentation Requests: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			fmt.Printf("<%d> Presentation Request(s) Found\n", len(requests))
			for _, request := range requests {
				fmt.Println(request.ProofRequestInstanceID)
			}

			resps, err := storage.ListPresentationResponses()
			if err != nil {
				fmt.Printf("Unable to read Presentation Responses: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			fmt.Printf("<%d> Presentation Response(s) Found\n", len(resps))
			for _, resp := range resps {
				fmt.Println(resp.ProofRequestInstanceID)
			}
			return nil
		},
	}

	newPresentationRequest = &cobra.Command{
		Use:     "new",
		Short:   "Create a new presentation request",
		Long:    "Create a new presentation request and store data to the local store.",
		Example: fmt.Sprintf("credwallet presentation new --%s=</input/file.json>", inputFileFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return err
			}
			defer storage.Close()

			// Retrieve the presentation request attributes
			presentationRequestFile := viper.GetString(inputFileFlag)
			presentationRequestJSON := viper.GetString(inputJSONFlag)
			if (presentationRequestFile == "" && presentationRequestJSON == "") || (presentationRequestFile != "" && presentationRequestJSON != "") {
				errMsg := "could not parse arguments: please specify either a presentation request file or json for presentation request attributes"
				logrus.Error(errMsg)
				return CmdErr(cmd, errors.New(errMsg))
			}

			inputData := []byte(presentationRequestJSON)
			if presentationRequestFile != "" {
				inputData, err = ioutil.ReadFile(presentationRequestFile)
				if err != nil {
					fmt.Printf("Could not read input file for presentation request JSON: %s\n", err.Error())
					return err
				}
			}

			var presentationRequest UnsignedCompositeProofRequestInstanceChallenge
			if err = json.Unmarshal(inputData, &presentationRequest); err != nil {
				fmt.Printf("Unable to unmarshal proof request JSON into object: %s\n", err.Error())
				return err
			}

			if err = storage.ValidatePresentationRequest(presentationRequest); err != nil {
				fmt.Printf("Error occured during validation: %s\n", err.Error())
				return err
			}

			// We have the presentation request object now - sign it and write to storage
			var verifierDID *ledger.DIDDoc
			verifierID := presentationRequest.ProofRequest.Verifier
			verifierDID, err = storage.ReadDIDDoc(verifierID)
			if err != nil {
				if verifierDID, err = storage.ReadCredDef(verifierID); err != nil {
					fmt.Printf("Error occured during retrieving verifier DID: %s\n", err.Error())
					return err
				}
			}

			verifierPK, err := storage.ReadPrivateKey(verifierID)
			if err != nil {
				fmt.Printf("Error occured during retrieving verifier Private Key: %s\n", err.Error())
				return err
			}

			presentationRequestSigned, err := BuildAndSignPresentationRequest(presentationRequest.ProofRequest.Description,
				*verifierDID,
				verifierPK,
				uuid.New().String(),
				presentationRequest.ProofResponseURL,
				presentationRequest.ProofRequest.Criteria,
				presentationRequest.SupportingCredentials,
				presentationRequest.Variables,
			)
			if err != nil {
				fmt.Printf("Error occured during while building Presentation Request: %s\n", err.Error())
				return err
			}

			if err = storage.WritePresentationRequest(*presentationRequestSigned); err != nil {
				fmt.Printf("Unable to write presentation request <%s> to storage: %s\n", presentationRequest.ProofRequestInstanceID, err.Error())
				return err
			}

			// Print the request to the console
			StructPrinter(presentationRequestSigned)
			return nil

		},
	}

	newPresentationResponse = &cobra.Command{
		Use:     "response",
		Short:   "Create a new presentation response to an existing request",
		Long:    "Create a new presentation response to an existing request and store data to the local store.",
		Example: fmt.Sprintf("credwallet presentation response --%s=presentation-request-id> --%s=<holder-did>", presentationRequestIDFlag, presentationHolderIDFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return err
			}
			defer storage.Close()

			// Retrieve the presentation request and presentation subject DID
			requestID := viper.GetString(presentationRequestIDFlag)
			holderID := viper.GetString(presentationHolderIDFlag)
			holderDID, err := storage.ReadDIDDoc(holderID)
			if err != nil {
				fmt.Printf("Error occured during retrieving subject DID: %s\n", err.Error())
				return err
			}
			holderPK, err := storage.ReadPrivateKey(holderID)
			if err != nil {
				fmt.Printf("Error occured during retrieving subject Private Key: %s\n", err.Error())
				return err
			}
			if requestID == "" {
				errMsg := "could not parse arguments: please specify presentation request ID"
				return CmdErr(cmd, fmt.Errorf(errMsg))
			}
			request, err := storage.ReadPresentationRequest(requestID)
			if err != nil {
				return fmt.Errorf("Error occured during retrieving Presentation Request: %s\n", err.Error())
			}

			// Retrieve the credentials stored in the local store
			credentials, err := storage.ListCredentialsForHolder(holderID)
			if err != nil {
				return fmt.Errorf("Error occured during retrieving credentials: %s\n", err.Error())
			}

			// Build the presentation response using the presentation request and the credentials, and sign it using the subject's Private Keyy
			response, err := BuildPresentationResponse(request, credentials, *holderDID, holderPK)
			if err != nil {
				fmt.Printf("Unable to build presentation response <%s>: %s\n", response.ProofRequestInstanceID, err.Error())
				return err
			}

			// Store to local store
			if err = storage.WritePresentationResponse(*response); err != nil {
				fmt.Printf("Unable to write presentation response <%s> to storage: %s\n", response.ProofRequestInstanceID, err.Error())
				return err
			}

			StructPrinter(response)
			return nil
		},
	}

	viewPresentationRequest = &cobra.Command{
		Use:     "viewreq",
		Short:   "view a presentation request",
		Long:    "View a presentation request, using its ID.",
		Example: fmt.Sprintf("credwallet pres viewreq --%s=<pres-request-id>", viewPresReqIDFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			id := viper.GetString(viewPresReqIDFlag)
			fmt.Printf("\n\nREQ ID: %s\n", id)
			req, err := storage.ReadPresentationRequest(id)
			if err != nil {
				fmt.Printf("Unable to read Presentation Request<%s>: %s\n", id, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(req)
			return nil
		},
	}

	viewPresentationResponse = &cobra.Command{
		Use:     "viewres",
		Short:   "view a presentation response",
		Long:    "View a presentation response, using its ID.",
		Example: fmt.Sprintf("credwallet pres viewres --%s=<pres-response-id>", viewPresRespIDFlag),
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := bolt.NewStorage()
			if err != nil {
				fmt.Printf("Unable to initiate bolt storage: %s\n", err.Error())
				return CmdErr(cmd, err)
			}
			defer storage.Close()

			id := viper.GetString(viewPresRespIDFlag)
			res, err := storage.ReadPresentationResponse(id)
			if err != nil {
				fmt.Printf("Unable to read Presentation Response<%s>: %s\n", id, err.Error())
				return CmdErr(cmd, err)
			}
			StructPrinter(res)
			return nil
		},
	}
)
