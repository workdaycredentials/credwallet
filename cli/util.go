package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func ValidateFlags(cmd ...*cobra.Command) {
	for _, c := range cmd {
		if err := viper.BindPFlags(c.PersistentFlags()); err != nil {
			panic(err)
		}
		if err := viper.BindPFlags(c.Flags()); err != nil {
			panic(err)
		}
	}
}

// TODO move to ledger-common
func BuildCredDef(controller, schemaID string) (*ledger.DIDDoc, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	id := did.GenerateDID(publicKey)
	keyID := fmt.Sprintf("%s#%s", id, did.InitialKey)
	pubKeys := make(map[string]ed25519.PublicKey)
	pubKeys[did.InitialKey] = publicKey
	services := []did.ServiceDef{
		{
			ID:              schemaID,
			Type:            "schema",
			ServiceEndpoint: schemaID,
		},
	}

	signer, err := proof.NewEd25519Signer(privateKey, keyID)
	if err != nil {
		logrus.WithError(err).Errorf("problem building signer with key: %s", keyID)
		return nil, nil, err
	}

	didDoc, err := ledger.GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyID,
		Signer:               signer,
		SignatureType:        proof.JCSEdSignatureType,
		PublicKeys:           pubKeys,
		Issuer:               controller,
		Services:             services,
	}.GenerateLedgerDIDDoc()
	return didDoc, privateKey, err
}

type CredDefInfo struct {
	ControllerID string
	SchemaID     string
}

func GetCredDefInfo(doc ledger.DIDDoc) (*CredDefInfo, error) {
	if len(doc.PublicKey) == 0 {
		return nil, errors.New("doc does not have any keys")
	}
	if len(doc.Service) == 0 {
		return nil, errors.New("doc does not have any services")
	}
	return &CredDefInfo{
		ControllerID: doc.PublicKey[0].Controller,
		SchemaID:     doc.Service[0].ID,
	}, nil
}

func BuildAndSignSchema(schemaInputJSON ledger.JSONSchemaMap, privateKey ed25519.PrivateKey, authorDIDDoc ledger.DIDDoc) (*ledger.Schema, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	if authorDIDDoc.IsEmpty() || authorDIDDoc.DIDDoc.IsEmpty() {
		logrus.Error("Author DID Doc not found.")
		return nil, errors.New("author DID not found in local store")
	}

	schema := ledger.Schema{
		Metadata: &ledger.Metadata{
			Type:         util.SchemaTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           ledger.GenerateSchemaID(authorDIDDoc.ID, util.Version_1_0),
			Name:         schemaInputJSON.Description(),
			Author:       authorDIDDoc.ID,
			Authored:     now,
		},
		JSONSchema: &ledger.JSONSchema{Schema: schemaInputJSON},
	}

	// Build signer and then sign
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	signer, err := proof.NewEd25519Signer(privateKey, authorDIDDoc.PublicKey[0].ID)
	if err != nil {
		return nil, err
	}
	if err := suite.Sign(schema, signer); err != nil {
		logrus.WithError(err).Error("Unable to sign schema.")
		return nil, err
	}

	return &schema, nil
}

func BuildAndSignCredential(credInputJSON, schemaID, subjectDID string, issuerDoc ledger.DIDDoc, issuerPrivateKey ed25519.PrivateKey) (*credential.VerifiableCredential, error) {
	var credData map[string]interface{}
	if err := json.Unmarshal([]byte(credInputJSON), &credData); err != nil {
		return nil, errors.New("could not unmarshal cred data")
	}

	metadata := credential.NewMetadataWithTimestamp(uuid.New().String(), issuerDoc.ID, schemaID, time.Now())
	keyRef := issuerDoc.PublicKey[0].ID
	signer, err := proof.NewEd25519Signer(issuerPrivateKey, keyRef)
	if err != nil {
		return nil, errors.New("could not build signer")
	}
	return credential.Builder{
		SubjectDID:    subjectDID,
		Data:          credData,
		Metadata:      &metadata,
		Signer:        signer,
		SignatureType: proof.JCSEdSignatureType,
	}.Build()
}

func BuildAndSignPresentationRequest(
	description string,
	verifierDoc ledger.DIDDoc,
	verifierPK ed25519.PrivateKey,
	prID string,
	url string,
	criteria []presentation.Criterion,
	supportingCreds []credential.VerifiableCredential,
	variables map[string]interface{}) (*presentation.CompositeProofRequestInstanceChallenge, error) {
	if prID == "" {
		return nil, fmt.Errorf("proof request instance ID is empty")
	}
	if criteria == nil {
		return nil, fmt.Errorf("criteria is nil")
	}
	proofRequest := presentation.CompositeProofRequest{
		ProofReqRespMetadata: presentation.ProofReqRespMetadata{},
		Description:          description,
		Verifier:             verifierDoc.ID,
		Criteria:             criteria,
	}
	presentationRequest := presentation.UnsignedCompositeProofRequestInstanceChallenge{
		ProofRequestInstanceID: prID,
		ProofResponseURL:       url,
		ProofRequest:           &proofRequest,
		SupportingCredentials:  supportingCreds,
		Variables:              variables,
	}

	// build signer and sign
	presentationRequestSigned := presentation.CompositeProofRequestInstanceChallenge{
		UnsignedCompositeProofRequestInstanceChallenge: presentationRequest,
	}

	keyID := verifierDoc.PublicKey[0].ID
	signer, err := proof.NewEd25519Signer(verifierPK, keyID)
	if err != nil {
		logrus.WithError(err).Errorf("problem building signer with key: %s", keyID)
		return nil, err
	}
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	if err != nil {
		logrus.WithError(err).Error("problem getting signature suite")
		return nil, err
	}
	err = suite.Sign(&presentationRequestSigned, signer)
	return &presentationRequestSigned, err
}

func BuildPresentationResponse(presentationRequest presentation.CompositeProofRequestInstanceChallenge,
	credentials []credential.VerifiableCredential,
	holderDID ledger.DIDDoc,
	holderPK ed25519.PrivateKey) (*presentation.CompositeProofResponseSubmission, error) {

	var unsignedCredentials []credential.UnsignedVerifiableCredential
	for _, cred := range credentials {
		unsignedCredentials = append(unsignedCredentials, cred.UnsignedVerifiableCredential)
	}

	signer, err := proof.NewEd25519Signer(holderPK, holderDID.PublicKey[0].ID)
	if err != nil {
		return nil, errors.New("could not build signer")
	}
	var fulfilledCriteria []presentation.FulfilledCriterion
	for _, criterion := range presentationRequest.ProofRequest.Criteria {
		if err := presentation.CheckVCsMatchCriterion(criterion, unsignedCredentials, nil); err == nil {
			fulfilledCriterion, err := presentation.FulfillCriterionForVCs(criterion, nil, unsignedCredentials, signer)
			if err != nil {
				return nil, fmt.Errorf("Error occured during fulfilling criterion: %s\n", err.Error())
			}
			fulfilledCriteria = append(fulfilledCriteria, *fulfilledCriterion)
			continue
		}
		return nil, fmt.Errorf("cred to satisfy criterion not found")
	}
	return presentation.GenerateCompositeProofResponse(presentationRequest, fulfilledCriteria, signer)
}

// StructPrinter prints a struct as JSON to stdout
func StructPrinter(s interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "\t")
	encoder.Encode(s)
}

// IsJSON returns true if input is valid JSON, false otherwise
func IsJSON(maybeJSON []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(maybeJSON, &js) == nil
}

// CmdErr prints the help text for the command and prints an error
func CmdErr(cmd *cobra.Command, err error) error {
	fmt.Println(cmd.UsageString())
	return err
}
