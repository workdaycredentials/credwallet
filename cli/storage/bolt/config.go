package bolt

const (
	DIDBucket                   = "DIDs"
	PrivateKeyBucket            = "PrKeys"
	CredDefBucket               = "CredDefs"
	CredentialBucket            = "Credentials"
	SchemaBucket                = "Schemas"
	RevocationBucket            = "Revocations"
	PresentationRequestsBucket  = "PresentationRequests"
	PresentationResponsesBucket = "PresentationResponse"

	DBFilename = "credstore.db"
	DBFilemode = 0600
)

var (
	Buckets = []string{
		DIDBucket,
		PrivateKeyBucket,
		CredDefBucket,
		SchemaBucket,
		CredentialBucket,
		RevocationBucket,
		PresentationRequestsBucket,
		PresentationResponsesBucket,
	}
)
