package audit360

import "testing"

// TestVerifyReportRejectsBlankCertificateID pins the fail-closed rule for the
// certificate id. The id is not part of the signed payload; it is derived from
// the sealed payload digest, and verification recomputes it. The check used to
// be skipped when the field was empty or the old "unavailable" display
// sentinel, so anyone could strip the id from a valid report and still get
// Signed=true — a verifier could not tell which certificate it was holding.
func TestVerifyReportRejectsBlankCertificateID(t *testing.T) {
	for _, id := range []string{"", "unavailable"} {
		id := id
		t.Run("id="+id, func(t *testing.T) {
			rep, _ := sealedFixture(t)
			rep.CertificateID = id

			check, err := VerifyReport(rep, "")
			if err == nil {
				t.Fatalf("a sealed report whose certificate id is %q must not verify", id)
			}
			if check == nil || check.Signed {
				t.Fatalf("Signed = %v (check=%+v), want false", check != nil && check.Signed, check)
			}
		})
	}
}

// TestVerifyReportKeepsTheSealedCertificateID guards the other half: the id a
// report ships with is the id verification reports, and it is the one derived
// from the payload.
func TestVerifyReportKeepsTheSealedCertificateID(t *testing.T) {
	rep, _ := sealedFixture(t)
	if rep.CertificateID == "" {
		t.Fatal("fixture was sealed without a certificate id")
	}

	check, err := VerifyReport(rep, "")
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if check.CertificateID != rep.CertificateID {
		t.Fatalf("CertificateID = %q, want %q", check.CertificateID, rep.CertificateID)
	}
}
