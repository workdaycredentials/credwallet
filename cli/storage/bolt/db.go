package bolt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/sirupsen/logrus"
	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/ledger"
	"golang.org/x/crypto/ed25519"
)

type Storage struct {
	db *bolt.DB
}

func NewStorage() (*Storage, error) {
	mode := os.FileMode(DBFilemode)
	db, err := bolt.Open(DBFilename, mode, nil)
	if err != nil {
		logrus.WithError(err).Error("Could not access DB file")
		return nil, err
	}
	s := Storage{db: db}
	if err := s.initializeBuckets(); err != nil {
		logrus.WithError(err).Error("Failed to initialize bucket(s)")
		return nil, err
	}
	return &s, nil
}

func (s Storage) initializeBuckets() error {
	for _, b := range Buckets {
		err := s.db.Update(func(tx *bolt.Tx) error {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				logrus.WithError(err).Errorf("Could not create bucket: %s", b)
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s Storage) Close() error {
	if err := s.db.Close(); err != nil {
		logrus.WithError(err).Error("Could not close DB")
		return err
	}
	return nil
}

// DIDs //

func (s Storage) WriteDID(doc ledger.DIDDoc) error {
	// TODO validate DID Doc on write
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(DIDBucket))
		id := doc.ID
		didBytes, err := json.Marshal(doc)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal DID Doc.")
			return err
		}

		if err = b.Put([]byte(id), didBytes); err != nil {
			logrus.WithError(err).Error("Could not write DID to storage")
			return err
		}
		return nil
	})
	return err
}

func (s Storage) ReadDIDDoc(id string) (*ledger.DIDDoc, error) {
	var doc ledger.DIDDoc
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(DIDBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("DID not found: %s", id)
		}
		if err := json.Unmarshal(v, &doc); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into DID.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Errorf("Error retrieving DID Doc: %s", id)
	}
	return &doc, err
}

func (s Storage) ListDIDs() ([]ledger.DIDDoc, error) {
	var docs []ledger.DIDDoc
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(DIDBucket))
		err := b.ForEach(func(k, v []byte) error {
			var doc ledger.DIDDoc
			if err := json.Unmarshal(v, &doc); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into DID.")
				return err
			}
			docs = append(docs, doc)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving DIDs")
	}
	return docs, err
}

// Private Keys //

func (s Storage) WritePrivateKey(did string, pk ed25519.PrivateKey) error {
	// TODO validate DID + PK
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PrivateKeyBucket))
		return b.Put([]byte(did), []byte(hex.EncodeToString(pk)))
	})
	return err
}

func (s Storage) ReadPrivateKey(did string) (ed25519.PrivateKey, error) {
	var pk string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PrivateKeyBucket))
		v := b.Get([]byte(did))
		pk = string(v)
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Private Key")
	}
	return hex.DecodeString(pk)
}

// Cred Defs //

func (s Storage) WriteCredDef(doc ledger.DIDDoc, controllerDID, schemaID string) error {
	// Validations
	if err := s.validateDIDAndSchema(controllerDID, schemaID); err != nil {
		logrus.WithError(err).Error("Could not validate controller and/or schema")
		return err
	}

	if len(doc.Service) == 0 {
		return errors.New("cred definition must have at least one service defined")
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredDefBucket))
		id := doc.ID
		didBytes, err := json.Marshal(doc)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal Cred Def DID Doc.")
			return err
		}
		if err = b.Put([]byte(id), didBytes); err != nil {
			logrus.WithError(err).Error("Could not write Cred Def DID to storage")
			return err
		}
		return nil
	})
	return err
}

func (s Storage) validateDIDAndSchema(controllerDID, schemaID string) error {
	doc, err := s.ReadDIDDoc(controllerDID)
	if err != nil {
		return err
	}
	if doc == nil {
		return fmt.Errorf("could not resolve DID Doc: %s", controllerDID)
	}

	schema, err := s.ReadSchema(schemaID)
	if err != nil {
		return err
	}
	if schema == nil {
		return fmt.Errorf("could not resolve Schema: %s", schemaID)
	}

	return nil
}

func (s Storage) ReadCredDef(id string) (*ledger.DIDDoc, error) {
	var doc ledger.DIDDoc
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredDefBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("cred def not found: %s", id)
		}
		if err := json.Unmarshal(v, &doc); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into DID.")
			return err
		}
		return nil
	})
	if err != nil {
		fmt.Printf("IT IS: %s\n", id)
		logrus.WithError(err).Error("Error retrieving Cred Def DID Doc.")
	}
	return &doc, err
}

func (s Storage) ListCredDefs() ([]ledger.DIDDoc, error) {
	var docs []ledger.DIDDoc
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredDefBucket))
		err := b.ForEach(func(k, v []byte) error {
			var doc ledger.DIDDoc
			if err := json.Unmarshal(v, &doc); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Cred Def.")
				return err
			}
			docs = append(docs, doc)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Cred Defs")
	}
	return docs, err
}

// Schemas //

func (s Storage) WriteSchema(schema ledger.Schema) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(SchemaBucket))
		schemaBytes, err := json.Marshal(schema)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal schema into bytes.")
			return err
		}
		return b.Put([]byte(schema.ID), schemaBytes)
	})
}

func (s Storage) ReadSchema(id string) (*ledger.Schema, error) {
	var schema ledger.Schema
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(SchemaBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("schema not found: %s", id)
		}
		if err := json.Unmarshal(v, &schema); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into Schema.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Schema")
	}
	return &schema, err
}

func (s Storage) ListSchemas() ([]ledger.Schema, error) {
	var schemas []ledger.Schema
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(SchemaBucket))
		err := b.ForEach(func(k, v []byte) error {
			var schema ledger.Schema
			if err := json.Unmarshal(v, &schema); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Schema.")
				return err
			}
			schemas = append(schemas, schema)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving DIDs")
	}
	return schemas, err
}

// Credentials //

func (s Storage) WriteCredential(cred credential.VerifiableCredential) error {
	// TODO validate credential is compliant with schema, schema exists, issuer is a cred def
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredentialBucket))
		id := cred.ID
		credBytes, err := json.Marshal(cred)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal Credential.")
			return err
		}
		if err = b.Put([]byte(id), credBytes); err != nil {
			logrus.WithError(err).Error("Could not write Credential to storage")
			return err
		}
		return nil
	})
	return err
}

func (s Storage) ReadCredential(id string) (*credential.VerifiableCredential, error) {
	var cred credential.VerifiableCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredentialBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("credential not found: %s", id)
		}
		if err := json.Unmarshal(v, &cred); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into Credential.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Credential.")
	}
	return &cred, err
}

func (s Storage) ListCredentials() ([]credential.VerifiableCredential, error) {
	var creds []credential.VerifiableCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredentialBucket))
		err := b.ForEach(func(k, v []byte) error {
			var cred credential.VerifiableCredential
			if err := json.Unmarshal(v, &cred); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Credential.")
				return err
			}
			creds = append(creds, cred)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Credential")
	}
	return creds, err
}

func (s Storage) ListCredentialsForHolder(id string) ([]credential.VerifiableCredential, error) {
	// TODO this method can be improved to create a secondary index upon storage so iterating over each cred is not necessary
	var creds []credential.VerifiableCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(CredentialBucket))
		err := b.ForEach(func(k, v []byte) error {
			var cred credential.VerifiableCredential
			if err := json.Unmarshal(v, &cred); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Credential.")
				return err
			}
			// do the filtering
			if cred.CredentialSubject[credential.SubjectIDAttribute] == id {
				creds = append(creds, cred)
			}
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Credential")
	}
	return creds, err
}

// Revocations //

func (s Storage) WriteRevocation(revocation ledger.Revocation) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(RevocationBucket))
		id := revocation.Metadata.ID
		revBytes, err := json.Marshal(revocation)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal Revocation.")
			return err
		}
		if err = b.Put([]byte(id), revBytes); err != nil {
			logrus.WithError(err).Error("Could not write Revocation to storage")
			return err
		}
		return nil
	})
	return err
}

func (s Storage) ReadRevocation(id string) (*ledger.Revocation, error) {
	var rev ledger.Revocation
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(RevocationBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("revocation not found: %s", id)
		}
		if err := json.Unmarshal(v, &rev); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into Revocation.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Revocation.")
	}
	return &rev, err
}

func (s Storage) ListRevocations() ([]ledger.Revocation, error) {
	var revs []ledger.Revocation
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(RevocationBucket))
		err := b.ForEach(func(k, v []byte) error {
			var rev ledger.Revocation
			if err := json.Unmarshal(v, &rev); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Revocation.")
				return err
			}
			revs = append(revs, rev)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Revocation")
	}
	return revs, err
}

func (s Storage) WritePresentationRequest(presentationRequest presentation.CompositeProofRequestInstanceChallenge) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationRequestsBucket))
		proofRequestBytes, err := json.Marshal(presentationRequest)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal proof request into bytes.")
			return err
		}
		return b.Put([]byte(presentationRequest.ProofRequestInstanceID), proofRequestBytes)
	})
}

func (s Storage) ReadPresentationRequest(id string) (presentation.CompositeProofRequestInstanceChallenge, error) {
	var presentationRequest presentation.CompositeProofRequestInstanceChallenge
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationRequestsBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("proof request not found: %s", id)
		}
		if err := json.Unmarshal(v, &presentationRequest); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into presentation request.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving presentation request")
	}
	return presentationRequest, err
}

func (s Storage) ListPresentationRequests() ([]presentation.CompositeProofRequestInstanceChallenge, error) {
	var presentationRequests []presentation.CompositeProofRequestInstanceChallenge
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationRequestsBucket))
		err := b.ForEach(func(k, v []byte) error {
			var presentationRequest presentation.CompositeProofRequestInstanceChallenge
			if err := json.Unmarshal(v, &presentationRequest); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Proof Request.")
				return err
			}
			presentationRequests = append(presentationRequests, presentationRequest)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Presentation Requests")
	}
	return presentationRequests, err
}

func (s Storage) ValidatePresentationRequest(pr presentation.UnsignedCompositeProofRequestInstanceChallenge) error {
	if _, err := s.ReadDIDDoc(pr.ProofRequest.Verifier); err != nil {
		logrus.WithError(err).Warn("Error during validating verifier DID from DID storage; falling back to Cred Def storage.")
		if _, err := s.ReadCredDef(pr.ProofRequest.Verifier); err != nil {
			logrus.WithError(err).Warn("Error during validating verifier DID.")
			return err
		}
	}

	// For each criterion validate the issuer and schema exist
	for _, criterion := range pr.ProofRequest.Criteria {
		for _, issuerDID := range criterion.Issuers.DIDs {
			credDef, err := s.ReadCredDef(issuerDID)
			if err != nil {
				logrus.WithError(err).Error("Error during validating issuer DID.")
				return err
			}

			// Now check schema id
			schemaID := getSchemaIDFromPresentation(criterion.Schema)
			if credDef.Service[0].ID != schemaID {
				return fmt.Errorf("schema ID in Cred Def<%s> did not match Schema ID in criteria<%s>", credDef.Service[0].ID, schemaID)
			}

			// make sure schema exists
			if _, err := s.ReadSchema(schemaID); err != nil {
				logrus.WithError(err).Errorf("Error getting schema: %s", schemaID)
				return err
			}
		}
	}
	return nil
}

func getSchemaIDFromPresentation(s presentation.SchemaReq) string {
	if s.SchemaID != "" {
		return s.SchemaID
	}
	return fmt.Sprintf("%s;id=%s;version=%s", s.AuthorDID, s.ResourceIdentifier, strings.ReplaceAll(s.SchemaVersionRange, "^", ""))
}

func (s Storage) WritePresentationResponse(presentationResponse presentation.CompositeProofResponseSubmission) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationResponsesBucket))
		proofResponseBytes, err := json.Marshal(presentationResponse)
		if err != nil {
			logrus.WithError(err).Error("Could not marshal proof request into bytes.")
			return err
		}
		return b.Put([]byte(presentationResponse.UnsignedCompositeProofResponseSubmission.ID), proofResponseBytes)
	})
}

func (s Storage) ReadPresentationResponse(id string) (presentation.CompositeProofResponseSubmission, error) {
	var presentationResponse presentation.CompositeProofResponseSubmission
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationResponsesBucket))
		v := b.Get([]byte(id))
		if len(v) == 0 {
			return fmt.Errorf("proof response not found: %s", id)
		}
		if err := json.Unmarshal(v, &presentationResponse); err != nil {
			logrus.WithError(err).Error("Unable to marshal JSON into presentation response.")
			return err
		}
		return nil
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving presentation response.")
	}
	return presentationResponse, err
}

func (s Storage) ListPresentationResponses() ([]presentation.CompositeProofResponseSubmission, error) {
	var presentationResponses []presentation.CompositeProofResponseSubmission
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PresentationResponsesBucket))
		err := b.ForEach(func(k, v []byte) error {
			var response presentation.CompositeProofResponseSubmission
			if err := json.Unmarshal(v, &response); err != nil {
				logrus.WithError(err).Error("Unable to marshal JSON into Presentation Response.")
				return err
			}
			presentationResponses = append(presentationResponses, response)
			return nil
		})
		return err
	})
	if err != nil {
		logrus.WithError(err).Error("Error retrieving Presentation Responses")
	}
	return presentationResponses, err
}
