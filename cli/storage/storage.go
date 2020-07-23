package storage

import (
	"crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/ledger"
)

type Storage interface {
	DIDStorage
	KeyStorage
	CredDefStorage
	SchemaStorage
	CredentialStorage
	RevocationStorage
	PresentationStorage

	Close() error
}

type DIDStorage interface {
	WriteDID(doc ledger.DIDDoc) error
	ReadDIDDoc(id string) (*ledger.DIDDoc, error)
	ListDIDs() ([]ledger.DIDDoc, error)
}

type KeyStorage interface {
	WritePrivateKey(did string, pk ed25519.PrivateKey) error
	ReadPrivateKey(did string) (ed25519.PrivateKey, error)
}

type CredDefStorage interface {
	WriteCredDef(doc ledger.DIDDoc, controllerDID, schemaID string) error
	ReadCredDef(id string) (*ledger.DIDDoc, error)
	ListCredDefs() ([]ledger.DIDDoc, error)
}

type SchemaStorage interface {
	WriteSchema(schema ledger.Schema) error
	ReadSchema(id string) (*ledger.Schema, error)
	ListSchemas() ([]ledger.Schema, error)
}

// TODO key credentials by subject
type CredentialStorage interface {
	WriteCredential(cred credential.VerifiableCredential) error
	ReadCredential(id string) (*credential.VerifiableCredential, error)
	ListCredentials() ([]credential.VerifiableCredential, error)
	ListCredentialsForHolder(id string) ([]credential.VerifiableCredential, error)
}

type RevocationStorage interface {
	WriteRevocation(revocation ledger.Revocation) error
	ReadRevocation(id string) (*ledger.Revocation, error)
	ListRevocations() ([]ledger.Revocation, error)
}

type PresentationStorage interface {
	PresentationRequestStorage
	PresentationResponseStorage
}

type PresentationRequestStorage interface {
	WritePresentationRequest(presentationRequest presentation.CompositeProofRequestInstanceChallenge) error
	ReadPresentationRequest(id string) (presentation.CompositeProofRequestInstanceChallenge, error)
	ListPresentationRequests() ([]presentation.CompositeProofRequestInstanceChallenge, error)
}

type PresentationResponseStorage interface {
	WritePresentationResponse(presentationResponse presentation.CompositeProofResponseSubmission) error
	ReadPresentationResponse(id string) (presentation.CompositeProofResponseSubmission, error)
	ListPresentationResponses() ([]presentation.CompositeProofResponseSubmission, error)
}
