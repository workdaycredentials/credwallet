package bolt

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"

	"github.com/workdaycredentials/ledger-common/did"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/credwallet/cli"
)

const (
	TestSchemaFile               = "../../../testdata/sample-schema.json"
	TestCredDataFile             = "../../../testdata/sample-creddata.json"
	TestPresentationRequestsFile = "../../../testdata/sample-presentation-request.json"
)

func TestDIDStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	t.Run("Write DID", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)
	})

	t.Run("Read DID", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		gotDoc, err := storage.ReadDIDDoc(doc.ID)
		assert.NoError(t, err)
		assert.Equal(t, doc, gotDoc)

		// Read bad DID
		baddoc, err := storage.ReadDIDDoc("badid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DID not found")
		assert.Empty(t, baddoc)
	})

	t.Run("List DIDs", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		docs, err := storage.ListDIDs()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(docs), 1)
		assert.Contains(t, docs, *doc)
	})

	assert.NoError(t, storage.Close())
}

func TestKeyStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	t.Run("Write and read key happy path", func(t *testing.T) {
		pubKey, privKey, _ := ed25519.GenerateKey(nil)
		id := did.GenerateDID(pubKey)
		err = storage.WritePrivateKey(id, privKey)
		assert.NoError(t, err)

		privKeyRead, err := storage.ReadPrivateKey(id)
		assert.NoError(t, err)
		assert.Equal(t, privKey, privKeyRead)
	})

	t.Run("Read bad key", func(t *testing.T) {
		_, sk, _ := ed25519.GenerateKey(nil)
		skGenr := hex.EncodeToString(sk)

		skRead, err := storage.ReadPrivateKey("badid")
		assert.NoError(t, err)
		assert.NotEqual(t, skGenr, skRead)
		assert.NoError(t, storage.Close())
	})

	assert.NoError(t, storage.Close())
}

func TestCredDefStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	testSchemaID := "schemaID"
	testAbsentSchemaID := "absentSchemaID"

	authorDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	err = storage.WriteDID(*authorDoc)
	assert.NoError(t, err)

	inputData, err := ioutil.ReadFile(TestSchemaFile)
	assert.NoError(t, err)

	var schemaInput ledger.JSONSchemaMap
	err = json.Unmarshal(inputData, &schemaInput)
	assert.NoError(t, err)

	s := ledger.Schema{
		Metadata: &ledger.Metadata{
			Type:         util.SchemaTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           testSchemaID,
			Name:         schemaInput.Description(),
			Author:       authorDoc.ID,
			Authored:     time.Now().UTC().Format(time.RFC3339),
		},
		JSONSchema: &ledger.JSONSchema{Schema: schemaInput},
	}

	err = storage.WriteSchema(s)
	assert.NoError(t, err)

	t.Run("Write Cred Def", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		// Now build cred def
		credDef, _, err := cli.BuildCredDef(doc.ID, testSchemaID)
		assert.NoError(t, err)
		err = storage.WriteCredDef(*credDef, doc.ID, testSchemaID)
		assert.NoError(t, err)
	})

	t.Run("Write Bad Cred Def", func(t *testing.T) {
		// Now build cred def
		credDef, _, err := cli.BuildCredDef("missingID", testSchemaID)
		assert.NoError(t, err)
		err = storage.WriteCredDef(*credDef, "missingID", testSchemaID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DID not found")
	})

	t.Run("Write Cred Def Absent Schema", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		credDef, _, err := cli.BuildCredDef(doc.ID, testAbsentSchemaID)
		assert.NoError(t, err)
		err = storage.WriteCredDef(*credDef, doc.ID, testAbsentSchemaID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "schema not found")
	})

	t.Run("Read Cred Def", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		// Now build cred def
		credDef, _, err := cli.BuildCredDef(doc.ID, testSchemaID)
		assert.NoError(t, err)
		err = storage.WriteCredDef(*credDef, doc.ID, testSchemaID)
		assert.NoError(t, err)

		// Read it
		foundDef, err := storage.ReadCredDef(credDef.ID)
		assert.NoError(t, err)
		assert.Equal(t, credDef, foundDef)
	})

	t.Run("List Cred Defs", func(t *testing.T) {
		doc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*doc)
		assert.NoError(t, err)

		// Now build cred def
		credDef, _, err := cli.BuildCredDef(doc.ID, testSchemaID)
		assert.NoError(t, err)
		err = storage.WriteCredDef(*credDef, doc.ID, testSchemaID)
		assert.NoError(t, err)

		credDefs, err := storage.ListCredDefs()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(credDefs), 1)
		assert.Contains(t, credDefs, *credDef)
	})

	assert.NoError(t, storage.Close())
}

func TestSchemaStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	t.Run("Write Schema to DB", func(t *testing.T) {
		authorDoc, pk := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

		err = storage.WriteDID(*authorDoc)
		assert.NoError(t, err)

		inputData, err := ioutil.ReadFile(TestSchemaFile)
		assert.NoError(t, err)

		var schemaInput ledger.JSONSchemaMap
		err = json.Unmarshal(inputData, &schemaInput)
		assert.NoError(t, err)

		schemaObj, err := cli.BuildAndSignSchema(schemaInput, pk, *authorDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*schemaObj)
		assert.NoError(t, err)
	})

	t.Run("Write and Read Schema from DB", func(t *testing.T) {
		authorDoc, pk := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*authorDoc)
		assert.NoError(t, err)

		inputData, err := ioutil.ReadFile(TestSchemaFile)
		assert.NoError(t, err)

		var schemaInput ledger.JSONSchemaMap
		err = json.Unmarshal(inputData, &schemaInput)
		assert.NoError(t, err)

		schemaObj, err := cli.BuildAndSignSchema(schemaInput, pk, *authorDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*schemaObj)
		assert.NoError(t, err)

		schemaExtracted, err := storage.ReadSchema(schemaObj.ID)
		assert.NoError(t, err)
		assert.Equal(t, schemaObj, schemaExtracted)
	})

	t.Run("List Schemas", func(t *testing.T) {
		authorDoc, pk := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*authorDoc)
		assert.NoError(t, err)

		inputData, err := ioutil.ReadFile(TestSchemaFile)
		assert.NoError(t, err)

		var schemaInput ledger.JSONSchemaMap
		err = json.Unmarshal(inputData, &schemaInput)
		assert.NoError(t, err)

		schema, err := cli.BuildAndSignSchema(schemaInput, pk, *authorDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*schema)
		assert.NoError(t, err)

		schemas, err := storage.ListSchemas()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(schemas), 1)
		assert.Contains(t, schemas, *schema)
	})

	assert.NoError(t, storage.Close())
}

func TestCredentialStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	schemaInputBytes, err := ioutil.ReadFile(TestSchemaFile)
	assert.NoError(t, err)

	var schemaInput ledger.JSONSchemaMap
	err = json.Unmarshal(schemaInputBytes, &schemaInput)
	assert.NoError(t, err)

	credInputBytes, err := ioutil.ReadFile(TestCredDataFile)
	assert.NoError(t, err)

	t.Run("Write and Read Credential", func(t *testing.T) {
		// Create issuer DID
		issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*issuerDoc)
		assert.NoError(t, err)

		// Register the s
		s, err := cli.BuildAndSignSchema(schemaInput, issuerPrivKey, *issuerDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*s)
		assert.NoError(t, err)

		// Create the cred def
		credDef, pk, err := cli.BuildCredDef(issuerDoc.ID, s.ID)
		assert.NoError(t, err)

		// Register the cred def private key
		err = storage.WritePrivateKey(credDef.ID, pk)
		assert.NoError(t, err)

		// Create subject DID
		subjectDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*subjectDoc)
		assert.NoError(t, err)

		// Create cred
		cred, err := cli.BuildAndSignCredential(string(credInputBytes), s.ID, subjectDoc.ID, *issuerDoc, issuerPrivKey)
		assert.NoError(t, err)

		// Store cred
		err = storage.WriteCredential(*cred)
		assert.NoError(t, err)

		// Read cred
		readCred, err := storage.ReadCredential(cred.ID)
		assert.NoError(t, err)

		// Make sure it's what we expect!
		assert.Equal(t, cred, readCred)

		// Verify data
		expectedClaims := map[string]interface{}{
			credential.SubjectIDAttribute: subjectDoc.ID,
			"firstName":                   "Alice",
			"lastName":                    "Bobsworth",
			"suffix":                      "III",
		}
		issuerPubKey := issuerPrivKey.Public().(ed25519.PublicKey)
		assert.Equal(t, expectedClaims, readCred.CredentialSubject)

		// Verify claim proofs
		assert.NoError(t, credential.VerifyClaim(readCred, credential.SubjectIDAttribute, issuerPubKey))
		assert.NoError(t, credential.VerifyClaim(readCred, "firstName", issuerPubKey))
		assert.NoError(t, credential.VerifyClaim(readCred, "lastName", issuerPubKey))
		assert.NoError(t, credential.VerifyClaim(readCred, "suffix", issuerPubKey))

		// Verify outer proof
		suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
		assert.NoError(t, err)

		verifier := proof.Ed25519Verifier{PubKey: issuerPubKey}
		err = suite.Verify(readCred, &verifier)
		assert.NoError(t, err)
	})

	t.Run("Read Bad Credential", func(t *testing.T) {
		cred, err := storage.ReadCredential("badID")
		assert.Error(t, err)
		assert.Empty(t, cred)
		assert.Contains(t, err.Error(), "credential not found")
	})

	t.Run("List Credentials", func(t *testing.T) {
		// Create issuer DID
		issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*issuerDoc)
		assert.NoError(t, err)

		// Create signer with issuer DID
		signer, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// Create subject DID
		subjectDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*subjectDoc)
		assert.NoError(t, err)

		testSchemaID := "nameSchemaID"
		metadata := credential.NewMetadataWithTimestamp(uuid.New().String(), issuerDoc.ID, testSchemaID, time.Now())
		cred, err := credential.Builder{
			SubjectDID: subjectDoc.ID,
			Data: map[string]interface{}{
				"firstName": "Alice",
				"lastName":  "Bobsworth",
			},
			Metadata:      &metadata,
			Signer:        signer,
			SignatureType: proof.JCSEdSignatureType,
		}.Build()
		assert.NoError(t, err)

		// Store cred
		err = storage.WriteCredential(*cred)
		assert.NoError(t, err)

		creds, err := storage.ListCredentials()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(creds), 1)
		assert.Contains(t, creds, *cred)

		listed, err := storage.ListCredentialsForHolder(subjectDoc.ID)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(listed), 1)

		listedBad, err := storage.ListCredentialsForHolder("badID")
		assert.NoError(t, err)
		assert.Equal(t, 0, len(listedBad))
	})

	assert.NoError(t, storage.Close())
}

func TestRevocationStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	schemaInputBytes, err := ioutil.ReadFile(TestSchemaFile)
	assert.NoError(t, err)

	var schemaInput ledger.JSONSchemaMap
	err = json.Unmarshal(schemaInputBytes, &schemaInput)
	assert.NoError(t, err)

	credInputBytes, err := ioutil.ReadFile(TestCredDataFile)
	assert.NoError(t, err)

	t.Run("Create, Write and Read Revocation", func(t *testing.T) {
		// Create issuer DID
		issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*issuerDoc)
		assert.NoError(t, err)

		// Register the s
		s, err := cli.BuildAndSignSchema(schemaInput, issuerPrivKey, *issuerDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*s)
		assert.NoError(t, err)

		// Create the cred def
		credDef, pk, err := cli.BuildCredDef(issuerDoc.ID, s.ID)
		assert.NoError(t, err)

		// Register the cred def private key
		err = storage.WritePrivateKey(credDef.ID, pk)
		assert.NoError(t, err)

		// Create signer with issuer DID
		signer, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// Create subject DID
		subjectDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*subjectDoc)
		assert.NoError(t, err)

		// Create cred
		cred, err := cli.BuildAndSignCredential(string(credInputBytes), s.ID, subjectDoc.ID, *issuerDoc, issuerPrivKey)
		assert.NoError(t, err)

		// Store cred
		err = storage.WriteCredential(*cred)
		assert.NoError(t, err)

		// Create revocation for the cred
		revocation, err := ledger.GenerateLedgerRevocation(cred.ID, issuerDoc.ID, signer, proof.JCSEdSignatureType)
		assert.NoError(t, err)

		// Store revocation
		err = storage.WriteRevocation(*revocation)
		assert.NoError(t, err)

		// Read revocation to verify it's there
		readRev, err := storage.ReadRevocation(revocation.Metadata.ID)
		assert.NoError(t, err)
		assert.Equal(t, revocation, readRev)
	})

	t.Run("Read Bad Rev", func(t *testing.T) {
		badRev, err := storage.ReadRevocation("badID")
		assert.Error(t, err)
		assert.Empty(t, badRev)
	})

	t.Run("List Revocations", func(t *testing.T) {
		// Create issuer DID
		issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*issuerDoc)
		assert.NoError(t, err)

		// Register the schema
		schema, err := cli.BuildAndSignSchema(schemaInput, issuerPrivKey, *issuerDoc)
		assert.NoError(t, err)

		err = storage.WriteSchema(*schema)
		assert.NoError(t, err)

		// Create the cred def
		credDef, pk, err := cli.BuildCredDef(issuerDoc.ID, schema.ID)
		assert.NoError(t, err)

		// Register the cred def private key
		err = storage.WritePrivateKey(credDef.ID, pk)
		assert.NoError(t, err)

		// Create signer with issuer DID
		signer, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// Create subject DID
		subjectDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		err = storage.WriteDID(*subjectDoc)
		assert.NoError(t, err)

		// Create cred
		cred, err := cli.BuildAndSignCredential(string(credInputBytes), schema.ID, subjectDoc.ID, *issuerDoc, issuerPrivKey)
		assert.NoError(t, err)

		// Store cred
		err = storage.WriteCredential(*cred)
		assert.NoError(t, err)

		// Create revocation for the cred
		revocation, err := ledger.GenerateLedgerRevocation(cred.ID, issuerDoc.ID, signer, proof.JCSEdSignatureType)
		assert.NoError(t, err)

		// Store revocation
		err = storage.WriteRevocation(*revocation)
		assert.NoError(t, err)

		revocations, err := storage.ListRevocations()
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(revocations), 1)
		assert.Contains(t, revocations, *revocation)
	})

	assert.NoError(t, storage.Close())
}

func TestPresentationStorage(t *testing.T) {
	storage, err := NewStorage()
	assert.NoError(t, err)

	schemaFile, err := ioutil.ReadFile(TestSchemaFile)
	assert.NoError(t, err)

	var schemaInput ledger.JSONSchemaMap
	err = json.Unmarshal(schemaFile, &schemaInput)
	assert.NoError(t, err)

	schemaAuthorDID, pk := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	err = storage.WriteDID(*schemaAuthorDID)
	assert.NoError(t, err)
	schemaObj, err := cli.BuildAndSignSchema(schemaInput, pk, *schemaAuthorDID)
	assert.NoError(t, err)
	err = storage.WriteSchema(*schemaObj)
	assert.NoError(t, err)
	schemaResourceID, err := schema.ExtractSchemaResourceID(schemaObj.ID)
	assert.NoError(t, err)

	issuerDID, issuerPK := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	err = storage.WriteDID(*issuerDID)
	assert.NoError(t, err)

	verifierDID, verifierPK := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	err = storage.WriteDID(*verifierDID)
	assert.NoError(t, err)

	attributeReq := presentation.AttributeReq{
		AttributeName: "firstName",
		Required:      true,
	}
	schemaReq := presentation.SchemaReq{
		AuthorDID:          schemaAuthorDID.ID,
		ResourceIdentifier: schemaResourceID,
		SchemaVersionRange: "^1.0",
		Attributes:         []presentation.AttributeReq{attributeReq},
	}
	criterion := presentation.Criterion{
		Description: "Contact Information",
		Reason:      "Send information regarding your application",
		Issuers:     presentation.Issuers{DIDs: []string{issuerDID.ID}},
		MaxRequired: 1,
		MinRequired: 1,
		Schema:      schemaReq,
	}
	presentationRequest, err := cli.BuildAndSignPresentationRequest(
		"Credit card application information",
		*verifierDID,
		verifierPK,
		uuid.New().String(),
		"https://responseendppint.com/path",
		[]presentation.Criterion{criterion},
		nil,
		nil)

	// Populate credential

	// Create the cred def
	credDef, pk, err := cli.BuildCredDef(issuerDID.ID, schemaObj.ID)
	assert.NoError(t, err)

	// Register the cred def private key
	err = storage.WritePrivateKey(credDef.ID, pk)
	assert.NoError(t, err)

	// Create signer with issuer DID

	// Create subject DID
	subjectDoc, subjectPK := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	err = storage.WriteDID(*subjectDoc)
	assert.NoError(t, err)

	credInputBytes, err := ioutil.ReadFile(TestCredDataFile)
	assert.NoError(t, err)

	// Create cred
	cred, err := cli.BuildAndSignCredential(string(credInputBytes), schemaObj.ID, subjectDoc.ID, *issuerDID, issuerPK)
	assert.NoError(t, err)

	// Store cred
	err = storage.WriteCredential(*cred)
	assert.NoError(t, err)

	// Read cred
	_, err = storage.ReadCredential(cred.ID)
	assert.NoError(t, err)

	t.Run("Write and Read Presentation Request from DB", func(t *testing.T) {
		err = storage.WritePresentationRequest(*presentationRequest)
		assert.NoError(t, err)

		presentationRequestExtracted, err := storage.ReadPresentationRequest(presentationRequest.ProofRequestInstanceID)
		assert.NoError(t, err)
		assert.Equal(t, *presentationRequest, presentationRequestExtracted)

	})

	t.Run("Generate and store Presentation Response to DB", func(t *testing.T) {
		credentials := []credential.VerifiableCredential{*cred}
		presentationResponse, err := cli.BuildPresentationResponse(*presentationRequest, credentials, *subjectDoc, subjectPK)
		assert.NoError(t, err)
		assert.NotEmpty(t, presentationResponse)
		err = storage.WritePresentationResponse(*presentationResponse)
		assert.NoError(t, err)

		presentationResponseExtracted, err := storage.ReadPresentationResponse(presentationResponse.UnsignedCompositeProofResponseSubmission.ID)
		assert.NoError(t, err)
		assert.Equal(t, *presentationResponse, presentationResponseExtracted)
	})

	t.Run("Read Bad Presentation", func(t *testing.T) {
		badRev, err := storage.ReadPresentationRequest("badID")
		assert.Error(t, err)
		assert.Empty(t, badRev)
	})

	t.Run("List Presentations", func(t *testing.T) {
		err = storage.WritePresentationRequest(*presentationRequest)
		assert.NoError(t, err)

		presentationRequests, err := storage.ListPresentationRequests()

		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(presentationRequests), 1)
		assert.Contains(t, presentationRequests, *presentationRequest)
	})
}
