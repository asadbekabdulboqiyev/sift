package certificate

import (
	"crypto/ed25519"
	"fmt"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
)

// validityPeriod is the human-readable validity shown in the seal and the PDF.
// It is a signed envelope field in ss-cert/v2.
const validityPeriod = "90 days"

// Issue renders, binds and signs one assessment. The document's SHA-256 is
// computed over the rendered body with a placeholder seal, then the real
// signature seal is applied for display — so the JSON, the HTML and the PDF all
// describe the same signed evidence and a tampered body still fails Verify.
//
// Both the CLI (`Sift certificate`) and the dashboard call this, so
// the two cannot produce certificates that verify differently.
//
// prevHash is the SHA-256 of the previously issued certificate JSON (empty for
// the first one). experimentReference identifies the source experiment/run this
// certificate attests to.
//
// The certificate is ss-cert/v2: the validity, the chain link, the source
// reference and the envelope signing time are part of the signed payload, so
// they cannot be edited after issuance.
func Issue(kp *attest.Keypair, a Assessment, prevHash string, experimentReference string) (*Certificate, error) {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("certificate: signing requires a valid Ed25519 private key")
	}
	if err := ValidateAssessmentInput(a); err != nil {
		return nil, err
	}
	bound := RenderHTML(a, "SIGNATURE_PLACEHOLDER", "KEY_PLACEHOLDER", a.SignedAt, VersionV2)
	cert, err := SignV2(kp, a, bound, Envelope{
		SignedAt:                a.SignedAt,
		ValidityPeriod:          validityPeriod,
		PreviousCertificateHash: prevHash,
		ExperimentReference:     experimentReference,
	})
	if err != nil {
		return nil, err
	}
	cert.CertificateID = CertificateID(cert)
	// The seal block is excluded from the document hash, so rendering the final
	// signature into it cannot invalidate the signature computed above. v2
	// verification additionally requires the stored page to equal this exact
	// rendering.
	cert.HTML = HTML(cert)
	return cert, nil
}
