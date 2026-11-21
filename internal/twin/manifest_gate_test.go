package twin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Manifest gate tests protect the provenance entry points that decide whether
// validation/backtest results may claim no leakage. All cases are deterministic
// and use only local temp files, so they are safe for parallel CI execution.

func mfWriteFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file %s: %v", path, err)
	}
	return path
}

func mfJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test payload: %v", err)
	}
	return string(b)
}

func mfPartition(datasetID, path, sha string, ids ...string) *SplitPartition {
	return &SplitPartition{DatasetID: datasetID, Path: path, SHA256: sha, RecordIDs: ids}
}

func mfSplitManifest(strategy, trainEnd, valStart string, train, val *SplitPartition) DatasetManifest {
	return DatasetManifest{
		SchemaVersion: DatasetManifestSchemaVersion,
		Kind:          ManifestKindBacktestPairs,
		CreatedAt:     "2026-01-01T00:00:00Z",
		Split: &ManifestSplit{
			Strategy:        strategy,
			Train:           train,
			Validation:      val,
			TrainEnd:        trainEnd,
			ValidationStart: valStart,
		},
	}
}

func mfValidManifest() DatasetManifest {
	return DatasetManifest{
		SchemaVersion: DatasetManifestSchemaVersion,
		Kind:          ManifestKindBacktestPairs,
		CreatedAt:     "2026-01-01T00:00:00Z",
		Datasets: []ManifestDataset{
			{ID: "train.json", Kind: "pairs_file", Path: "/data/train.json", RecordIDs: []string{"0"}},
		},
		Split: &ManifestSplit{
			Strategy:   "explicit_ids",
			Train:      &SplitPartition{DatasetID: "train.json", Path: "/data/train.json", RecordIDs: []string{"0"}},
			Validation: &SplitPartition{DatasetID: "val.json", Path: "/data/val.json", RecordIDs: []string{"1"}},
		},
	}
}

func mfIntPtr(v int) *int { return &v }

func mfJoinedReasons(res LeakageVerification) string {
	return strings.Join(append(append([]string{}, res.Reasons...), res.Summary), " | ")
}

// TestVerifyManifestSeparationGate guards the leakage verdict itself: missing
// provenance must stay UNVERIFIED, overlap must be DETECTED, and only proven
// disjoint evidence may become VERIFIED.
func TestVerifyManifestSeparationGate(t *testing.T) {
	tests := []struct {
		name           string
		manifest       DatasetManifest
		wantStatus     string
		wantVerified   bool
		wantLeakage    bool
		wantOverlap    int
		wantOverlapIDs []string
		wantChecks     []string
		wantSummary    string
		wantReason     string
	}{
		{
			name:        "nil_split_is_unverified",
			manifest:    DatasetManifest{SchemaVersion: DatasetManifestSchemaVersion, Kind: ManifestKindBacktestPairs},
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: split definition missing",
			wantReason:  "manifest split definition missing",
		},
		{
			name: "missing_train_partition_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				nil, mfPartition("val", "/data/val.json", "", "1")),
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: incomplete split partitions",
			wantReason:  "manifest split must define both train and validation partitions",
		},
		{
			name: "missing_validation_partition_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/train.json", "", "0"), nil),
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: incomplete split partitions",
			wantReason:  "manifest split must define both train and validation partitions",
		},
		{
			name: "train_without_provenance_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("", "", ""), mfPartition("val", "/data/val.json", "", "1")),
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: insufficient partition provenance",
			wantReason:  "train partition lacks sufficient provenance (IDs/hash/path)",
		},
		{
			name: "validation_without_provenance_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/train.json", "", "0"), mfPartition("", "", "")),
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: insufficient partition provenance",
			wantReason:  "validation partition lacks sufficient provenance (IDs/hash/path)",
		},
		{
			name: "whitespace_only_provenance_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				&SplitPartition{RecordIDs: []string{"  ", ""}, SHA256: "\t", Path: " ", DatasetID: "\n"},
				&SplitPartition{RecordIDs: []string{" "}, SHA256: "  ", Path: "\t", DatasetID: ""}),
			wantStatus:  LeakageStatusUnverified,
			wantSummary: "unverified: insufficient partition provenance",
			wantReason:  "train partition lacks sufficient provenance (IDs/hash/path)",
		},
		{
			name: "overlapping_ids_are_leakage",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/train.json", "aaaa", "0", "1", "2"),
				mfPartition("val", "/data/val.json", "bbbb", "2", "3", "4")),
			wantStatus:     LeakageStatusLeakageDetected,
			wantLeakage:    true,
			wantOverlap:    1,
			wantOverlapIDs: []string{"2"},
			wantChecks:     []string{"id_overlap_check"},
			wantSummary:    "leakage detected: overlapping record IDs",
			wantReason:     "train/validation ID overlap detected (1 IDs)",
		},
		{
			name: "multiple_overlaps_are_sorted_and_deduplicated",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/t", "aaaa", "b", "a", "c", "a", "d"),
				mfPartition("val", "/v", "bbbb", "c", "a", "e", "c")),
			wantStatus:     LeakageStatusLeakageDetected,
			wantLeakage:    true,
			wantOverlap:    2,
			wantOverlapIDs: []string{"a", "c"},
			wantChecks:     []string{"id_overlap_check"},
			wantSummary:    "leakage detected: overlapping record IDs",
			wantReason:     "train/validation ID overlap detected (2 IDs)",
		},
		{
			name: "same_sha_case_insensitive_with_disjoint_ids_is_verified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/train.json", "deadbeef", "0", "1"),
				mfPartition("val", "/data/val.json", "DEADBEEF", "2", "3")),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"id_overlap_check", "hash_equality_check"},
			wantSummary:  "verified: explicit disjoint train/validation record IDs",
			wantReason:   "no ID overlap detected across 2 train and 2 validation IDs",
		},
		{
			name: "same_path_after_clean_without_ids_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/shared.json", ""),
				mfPartition("val", "/data/shared/../shared.json", "")),
			wantStatus:  LeakageStatusUnverified,
			wantChecks:  []string{"path_equality_check"},
			wantSummary: "unverified: same source without explicit ID-level separation",
			wantReason:  "train/validation reference same source but explicit disjoint record IDs are missing",
		},
		{
			name: "same_dataset_id_without_ids_is_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("shared-id", "/data/train.json", ""),
				mfPartition("shared-id", "/data/val.json", "")),
			wantStatus:  LeakageStatusUnverified,
			wantChecks:  []string{"dataset_id_equality_check"},
			wantSummary: "unverified: same source without explicit ID-level separation",
			wantReason:  "train/validation reference same source but explicit disjoint record IDs are missing",
		},
		{
			name: "clean_separate_sources_with_disjoint_ids_is_verified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/data/train.json", "aaaa", "0", "1"),
				mfPartition("val", "/data/val.json", "bbbb", "2", "3")),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"id_overlap_check", "source_separation_check"},
			wantSummary:  "verified: explicit disjoint train/validation IDs with source provenance",
			wantReason:   "no ID overlap detected across 2 train and 2 validation IDs",
		},
		{
			name: "separate_files_strategy_without_ids_is_verified",
			manifest: mfSplitManifest("separate_files", "", "",
				mfPartition("train", "/data/train.json", "aaaa"),
				mfPartition("val", "/data/val.json", "bbbb")),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"source_separation_check"},
			wantSummary:  "verified: separate train/validation dataset sources",
			wantReason:   "different dataset sources with provenance; treated as separated",
		},
		{
			name: "ambiguous_source_strategy_without_ids_is_unverified",
			manifest: mfSplitManifest("unknown", "", "",
				mfPartition("train", "/data/train.json", "aaaa"),
				mfPartition("val", "/data/val.json", "bbbb")),
			wantStatus:  LeakageStatusUnverified,
			wantChecks:  []string{"source_separation_check"},
			wantSummary: "unverified: source separation not provable without IDs/strategy evidence",
			wantReason:  "different dataset sources provided but explicit record-ID separation not proven",
		},
		{
			name: "time_boundary_overlap_is_leakage",
			manifest: mfSplitManifest("time_cutoff", "2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z",
				mfPartition("train", "/t", "aaaa", "0"), mfPartition("val", "/v", "bbbb", "1")),
			wantStatus:  LeakageStatusLeakageDetected,
			wantLeakage: true,
			wantOverlap: 1,
			wantChecks:  []string{"id_overlap_check", "time_boundary_check"},
			wantSummary: "leakage detected: overlapping time boundary",
			wantReason:  "time boundary overlap: train_end",
		},
		{
			name: "ordered_time_boundary_with_disjoint_ids_is_verified",
			manifest: func() DatasetManifest {
				m := mfSplitManifest("time_cutoff", "", "",
					mfPartition("train", "/data/shared.json", "aaaa", "0"),
					mfPartition("val", "/data/shared.json", "bbbb", "1"))
				m.Split.Train.TimeEnd = "2026-01-01"
				m.Split.Validation.TimeStart = "2026-01-02"
				return m
			}(),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"id_overlap_check", "path_equality_check", "time_boundary_check"},
			wantSummary:  "verified: explicit disjoint train/validation record IDs",
			wantReason:   "time boundary OK:",
		},
		{
			name: "time_strategy_without_boundaries_or_ids_is_unverified",
			manifest: mfSplitManifest("time_cutoff", "", "",
				mfPartition("train", "/t", "aaaa"), mfPartition("val", "/v", "bbbb")),
			wantStatus:  LeakageStatusUnverified,
			wantChecks:  []string{"time_boundary_check"},
			wantSummary: "unverified: insufficient boundary evidence",
			wantReason:  "time boundary metadata incomplete/unparseable; cannot prove separation without explicit IDs",
		},
		{
			name: "unparseable_boundary_with_disjoint_ids_stays_verified",
			manifest: mfSplitManifest("time_cutoff", "not-a-time", "also-not-a-time",
				mfPartition("train", "/t", "aaaa", "0"), mfPartition("val", "/v", "bbbb", "1")),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"id_overlap_check", "time_boundary_check", "source_separation_check"},
			wantSummary:  "verified: explicit disjoint train/validation IDs with source provenance",
			wantReason:   "time boundary metadata incomplete/unparseable but explicit disjoint ID sets provided",
		},
		{
			name: "whitespace_ids_are_ignored_when_checking_overlap",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("train", "/t", "aaaa", " 0 ", "", "  1 "),
				mfPartition("val", "/v", "bbbb", "2", " ", "3")),
			wantStatus:   LeakageStatusVerifiedNoLeakage,
			wantVerified: true,
			wantChecks:   []string{"id_overlap_check", "source_separation_check"},
			wantSummary:  "verified: explicit disjoint train/validation IDs with source provenance",
			wantReason:   "no ID overlap detected across 2 train and 2 validation IDs",
		},
		{
			name: "ids_without_any_source_reference_stay_unverified",
			manifest: mfSplitManifest("explicit_ids", "", "",
				mfPartition("", "", "", "0"), mfPartition("", "", "", "1")),
			wantStatus:  LeakageStatusUnverified,
			wantChecks:  []string{"id_overlap_check"},
			wantSummary: "unverified: insufficient evidence to prove separation",
			wantReason:  "no ID overlap detected across 1 train and 1 validation IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act: the gate must never fabricate a verified result from thin evidence.
			got := VerifyManifestSeparation(tt.manifest)

			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q (summary=%q reasons=%v)", got.Status, tt.wantStatus, got.Summary, got.Reasons)
			}
			if got.Verified != tt.wantVerified {
				t.Fatalf("verified = %v, want %v (status=%q reasons=%v)", got.Verified, tt.wantVerified, got.Status, got.Reasons)
			}
			if got.LeakageDetected != tt.wantLeakage {
				t.Fatalf("leakage_detected = %v, want %v (status=%q reasons=%v)", got.LeakageDetected, tt.wantLeakage, got.Status, got.Reasons)
			}
			if got.OverlapCount != tt.wantOverlap {
				t.Fatalf("overlap_count = %d, want %d (status=%q reasons=%v)", got.OverlapCount, tt.wantOverlap, got.Status, got.Reasons)
			}
			if !reflect.DeepEqual(got.OverlapIDs, tt.wantOverlapIDs) {
				t.Fatalf("overlap_ids = %v, want %v (status=%q)", got.OverlapIDs, tt.wantOverlapIDs, got.Status)
			}
			if !reflect.DeepEqual(got.Checks, tt.wantChecks) {
				t.Fatalf("checks = %v, want %v (status=%q)", got.Checks, tt.wantChecks, got.Status)
			}
			if got.Summary != tt.wantSummary {
				t.Fatalf("summary = %q, want %q (reasons=%v)", got.Summary, tt.wantSummary, got.Reasons)
			}
			if !strings.Contains(mfJoinedReasons(got), tt.wantReason) {
				t.Fatalf("reasons/summary %q do not contain %q", mfJoinedReasons(got), tt.wantReason)
			}
			if got.Manifest == nil {
				t.Fatal("verification must retain a manifest reference for auditability")
			}
			if got.Manifest.Kind != tt.manifest.Kind {
				t.Fatalf("retained manifest kind = %q, want %q", got.Manifest.Kind, tt.manifest.Kind)
			}
		})
	}
}

// TestHasPartitionProvenanceGate protects the first gate in separation
// verification: whitespace-only metadata must never count as provenance.
func TestHasPartitionProvenanceGate(t *testing.T) {
	tests := []struct {
		name      string
		partition *SplitPartition
		want      bool
	}{
		{"nil_partition", nil, false},
		{"empty_partition", &SplitPartition{}, false},
		{"whitespace_only_fields", &SplitPartition{RecordIDs: []string{"", "  "}, SHA256: "\t", Path: "\n", DatasetID: " "}, false},
		{"record_ids_only", &SplitPartition{RecordIDs: []string{" ", "id-1"}}, true},
		{"sha_only", &SplitPartition{SHA256: "abc123"}, true},
		{"path_only", &SplitPartition{Path: "/data/train.json"}, true},
		{"dataset_id_only", &SplitPartition{DatasetID: "train"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPartitionProvenance(tt.partition); got != tt.want {
				t.Fatalf("hasPartitionProvenance(%+v) = %v, want %v", tt.partition, got, tt.want)
			}
		})
	}
}

// TestNonEmptyIDsGate protects ID trimming used by overlap detection; duplicate
// IDs are deliberately preserved here and removed later by normalizeIDList.
func TestNonEmptyIDsGate(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil_input", nil, []string{}},
		{"all_blank", []string{"", "  ", "\t", "\n"}, []string{}},
		{"trim_and_keep_duplicates", []string{" a ", "", "b", " a ", "  b  "}, []string{"a", "b", "a", "b"}},
		{"already_clean", []string{"0", "1"}, []string{"0", "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]string(nil), tt.input...)
			got := nonEmptyIDs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("nonEmptyIDs(%v) = %v, want %v", tt.input, got, tt.want)
			}
			if !reflect.DeepEqual(tt.input, original) {
				t.Fatalf("nonEmptyIDs mutated its input: got %v, want %v", tt.input, original)
			}
		})
	}
}

// TestIntersectIDsGate protects the exact overlap set reported to auditors:
// results are sorted and deduplicated so verdicts are stable across runs.
func TestIntersectIDsGate(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want []string
	}{
		{"no_overlap", []string{"0", "1"}, []string{"2", "3"}, nil},
		{"empty_left", nil, []string{"0"}, nil},
		{"empty_right", []string{"0"}, nil, nil},
		{"sorted_deduplicated_overlap", []string{"b", "a", "c", "a"}, []string{"c", "a", "d", "c"}, []string{"a", "c"}},
		{"full_overlap", []string{"x", "y"}, []string{"y", "x"}, []string{"x", "y"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intersectIDs(tt.a, tt.b)
			if len(tt.want) == 0 && len(got) != 0 {
				t.Fatalf("intersectIDs(%v, %v) = %v, want empty", tt.a, tt.b, got)
			}
			if len(tt.want) > 0 && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("intersectIDs(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestValidateManifestGate protects the input gate shared by every manifest
// consumer: schema/kind must be strict while IDs and timestamps are normalized.
func TestValidateManifestGate(t *testing.T) {
	tests := []struct {
		name        string
		build       func() DatasetManifest
		wantErrPart string
		verify      func(t *testing.T, got DatasetManifest)
	}{
		{
			name:  "blank_schema_gets_default",
			build: func() DatasetManifest { m := mfValidManifest(); m.SchemaVersion = "  "; return m },
			verify: func(t *testing.T, got DatasetManifest) {
				if got.SchemaVersion != DatasetManifestSchemaVersion {
					t.Fatalf("schema = %q, want %q", got.SchemaVersion, DatasetManifestSchemaVersion)
				}
			},
		},
		{
			name: "unsupported_schema_is_rejected",
			build: func() DatasetManifest {
				m := mfValidManifest()
				m.SchemaVersion = "sift.twin-dataset-manifest/v2"
				return m
			},
			wantErrPart: "unsupported manifest schema",
		},
		{
			name:        "blank_kind_is_rejected",
			build:       func() DatasetManifest { m := mfValidManifest(); m.Kind = "   "; return m },
			wantErrPart: "manifest kind must be",
		},
		{
			name:        "unknown_kind_is_rejected",
			build:       func() DatasetManifest { m := mfValidManifest(); m.Kind = "backtest_pairs_extra"; return m },
			wantErrPart: "manifest kind must be",
		},
		{
			name:  "kind_is_trimmed",
			build: func() DatasetManifest { m := mfValidManifest(); m.Kind = "  backtest_pairs  "; return m },
			verify: func(t *testing.T, got DatasetManifest) {
				if got.Kind != ManifestKindBacktestPairs {
					t.Fatalf("kind = %q, want %q", got.Kind, ManifestKindBacktestPairs)
				}
			},
		},
		{
			name:  "validate_compare_kind_is_accepted",
			build: func() DatasetManifest { m := mfValidManifest(); m.Kind = "\tvalidate_compare\n"; return m },
			verify: func(t *testing.T, got DatasetManifest) {
				if got.Kind != ManifestKindValidateCompare {
					t.Fatalf("kind = %q, want %q", got.Kind, ManifestKindValidateCompare)
				}
			},
		},
		{
			name: "ids_are_trimmed_and_deduplicated_everywhere",
			build: func() DatasetManifest {
				m := mfValidManifest()
				m.Datasets[0].RecordIDs = []string{" a ", "", "a", "  b  ", " "}
				m.Split.Train.RecordIDs = []string{" 0 ", "0", "", " 1 "}
				m.Split.Validation.RecordIDs = []string{" ", "2", "2 "}
				return m
			},
			verify: func(t *testing.T, got DatasetManifest) {
				if want := []string{"a", "b"}; !reflect.DeepEqual(got.Datasets[0].RecordIDs, want) {
					t.Fatalf("dataset ids = %v, want %v", got.Datasets[0].RecordIDs, want)
				}
				if want := []string{"0", "1"}; !reflect.DeepEqual(got.Split.Train.RecordIDs, want) {
					t.Fatalf("train ids = %v, want %v", got.Split.Train.RecordIDs, want)
				}
				if want := []string{"2"}; !reflect.DeepEqual(got.Split.Validation.RecordIDs, want) {
					t.Fatalf("validation ids = %v, want %v", got.Split.Validation.RecordIDs, want)
				}
			},
		},
		{
			name:  "created_at_is_preserved_when_set",
			build: mfValidManifest,
			verify: func(t *testing.T, got DatasetManifest) {
				if got.CreatedAt != "2026-01-01T00:00:00Z" {
					t.Fatalf("created_at = %q, want preserved value", got.CreatedAt)
				}
			},
		},
		{
			name:  "created_at_is_generated_when_blank",
			build: func() DatasetManifest { m := mfValidManifest(); m.CreatedAt = "  "; return m },
			verify: func(t *testing.T, got DatasetManifest) {
				if strings.TrimSpace(got.CreatedAt) == "" {
					t.Fatal("created_at must be generated when missing")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act: ValidateManifest is the public wrapper of normalizeAndValidateManifest.
			got, err := ValidateManifest(tt.build())
			if tt.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrPart)
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrPart)
				}
				if !reflect.DeepEqual(got, DatasetManifest{}) {
					t.Fatalf("invalid manifest must return zero value, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateManifest: %v", err)
			}
			if tt.verify != nil {
				tt.verify(t, got)
			}
		})
	}
}

// TestNormalizeAndValidateManifestDirect covers the internal normalizer directly
// and confirms it agrees with the public validation wrapper on clean input.
func TestNormalizeAndValidateManifestDirect(t *testing.T) {
	direct, err := normalizeAndValidateManifest(mfValidManifest())
	if err != nil {
		t.Fatalf("normalizeAndValidateManifest: %v", err)
	}
	public, err := ValidateManifest(mfValidManifest())
	if err != nil {
		t.Fatalf("ValidateManifest: %v", err)
	}
	if !reflect.DeepEqual(direct, public) {
		t.Fatalf("normalizer and public validator disagree: direct=%+v public=%+v", direct, public)
	}
}

// TestLoadManifestGate protects disk-based manifest ingestion: malformed or
// invalid files must be rejected while valid files are normalized on load.
func TestLoadManifestGate(t *testing.T) {
	tests := []struct {
		name        string
		body        func(t *testing.T) string
		skipWrite   bool
		wantErrPart string
		verify      func(t *testing.T, got DatasetManifest)
	}{
		{
			name: "valid_file_is_normalized",
			body: func(t *testing.T) string {
				return mfJSON(t, map[string]any{
					"schema_version": "",
					"kind":           "  backtest_pairs  ",
					"datasets": []map[string]any{{
						"id": "train.json", "record_ids": []string{" a ", "", "a", " b "},
					}},
					"split": map[string]any{
						"strategy":   "explicit_ids",
						"train":      map[string]any{"record_ids": []string{" 0 ", "", "0"}},
						"validation": map[string]any{"record_ids": []string{" 1 "}},
					},
				})
			},
			verify: func(t *testing.T, got DatasetManifest) {
				if got.SchemaVersion != DatasetManifestSchemaVersion {
					t.Fatalf("schema = %q, want %q", got.SchemaVersion, DatasetManifestSchemaVersion)
				}
				if got.Kind != ManifestKindBacktestPairs {
					t.Fatalf("kind = %q, want %q", got.Kind, ManifestKindBacktestPairs)
				}
				if want := []string{"a", "b"}; !reflect.DeepEqual(got.Datasets[0].RecordIDs, want) {
					t.Fatalf("dataset ids = %v, want %v", got.Datasets[0].RecordIDs, want)
				}
				if want := []string{"0"}; !reflect.DeepEqual(got.Split.Train.RecordIDs, want) {
					t.Fatalf("train ids = %v, want %v", got.Split.Train.RecordIDs, want)
				}
				if want := []string{"1"}; !reflect.DeepEqual(got.Split.Validation.RecordIDs, want) {
					t.Fatalf("validation ids = %v, want %v", got.Split.Validation.RecordIDs, want)
				}
			},
		},
		{
			name:        "malformed_json_is_rejected",
			body:        func(t *testing.T) string { return `{"schema_version": ` },
			wantErrPart: "parse manifest",
		},
		{
			name:        "missing_file_is_rejected",
			body:        func(t *testing.T) string { return "" },
			skipWrite:   true,
			wantErrPart: "read manifest",
		},
		{
			name: "unsupported_schema_in_file_is_rejected",
			body: func(t *testing.T) string {
				return mfJSON(t, map[string]any{"schema_version": "sift.twin-dataset-manifest/v9", "kind": ManifestKindBacktestPairs})
			},
			wantErrPart: "unsupported manifest schema",
		},
		{
			name: "invalid_kind_in_file_is_rejected",
			body: func(t *testing.T) string {
				return mfJSON(t, map[string]any{"schema_version": DatasetManifestSchemaVersion, "kind": "bogus"})
			},
			wantErrPart: "manifest kind must be",
		},
		{
			name: "invalid_file_error_mentions_invalid_manifest",
			body: func(t *testing.T) string {
				return mfJSON(t, map[string]any{"schema_version": "bad", "kind": ManifestKindBacktestPairs})
			},
			wantErrPart: "invalid manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: write raw JSON so LoadManifest, not WriteManifest, normalizes it.
			path := filepath.Join(t.TempDir(), "manifest.json")
			if !tt.skipWrite {
				path = mfWriteFile(t, filepath.Dir(path), "manifest.json", tt.body(t))
			}

			// Act.
			got, err := LoadManifest(path)
			if tt.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrPart)
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrPart)
				}
				if !reflect.DeepEqual(got, DatasetManifest{}) {
					t.Fatalf("failed load must return zero value, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadManifest: %v", err)
			}
			if tt.verify != nil {
				tt.verify(t, got)
			}
		})
	}
}

// TestHashBytesSHA256KnownVectors anchors the provenance hash to published
// SHA-256 digests so a broken hash implementation cannot silently pass.
func TestHashBytesSHA256KnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty_bytes", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"ascii_abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"trailing_newline", "hello\n", "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashBytesSHA256([]byte(tt.input)); got != tt.want {
				t.Fatalf("HashBytesSHA256(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestHashFileSHA256Gate covers determinism, content sensitivity, empty files,
// and missing files for the file-level provenance anchor.
func TestHashFileSHA256Gate(t *testing.T) {
	dir := t.TempDir()
	path := mfWriteFile(t, dir, "payload.bin", "abc")

	first, err := hashFileSHA256(path)
	if err != nil {
		t.Fatalf("hashFileSHA256(valid): %v", err)
	}
	second, err := hashFileSHA256(path)
	if err != nil {
		t.Fatalf("hashFileSHA256(valid, second call): %v", err)
	}
	if first != second {
		t.Fatalf("hash is not deterministic: %q then %q", first, second)
	}
	if want := HashBytesSHA256([]byte("abc")); first != want {
		t.Fatalf("file hash = %q, want byte hash %q", first, want)
	}

	// Content change must change the digest, otherwise stale provenance passes.
	changed := mfWriteFile(t, dir, "changed.bin", "abd")
	changedHash, err := hashFileSHA256(changed)
	if err != nil {
		t.Fatalf("hashFileSHA256(changed): %v", err)
	}
	if changedHash == first {
		t.Fatalf("different content produced identical hash %q", first)
	}

	empty := mfWriteFile(t, dir, "empty.bin", "")
	emptyHash, err := hashFileSHA256(empty)
	if err != nil {
		t.Fatalf("hashFileSHA256(empty): %v", err)
	}
	if want := HashBytesSHA256(nil); emptyHash != want {
		t.Fatalf("empty file hash = %q, want %q", emptyHash, want)
	}

	if _, err := hashFileSHA256(filepath.Join(dir, "missing.bin")); err == nil {
		t.Fatal("hashFileSHA256(missing file) must return an error")
	}
}

// TestApplyLeakageVerificationGate protects status propagation into the guard
// that downstream reports use; UNVERIFIED must never become proven or enforced.
func TestApplyLeakageVerificationGate(t *testing.T) {
	verifiedVer := LeakageVerification{
		Status:   LeakageStatusVerifiedNoLeakage,
		Verified: true,
		Checks:   []string{"id_overlap_check", "source_separation_check"},
		Summary:  "verified: explicit disjoint train/validation IDs with source provenance",
		Manifest: &DatasetManifest{Split: &ManifestSplit{Strategy: "explicit_ids"}},
	}

	tests := []struct {
		name             string
		guard            *LeakageGuard
		ver              LeakageVerification
		wantStatus       string
		wantVerified     bool
		wantProven       bool
		wantEnforced     bool
		wantOverlapCount *int
		wantChecks       []string
		wantMethod       string
		wantReasonParts  []string
		wantPreserveMeta bool
	}{
		{
			name:            "nil_guard_accepts_verified_result",
			ver:             verifiedVer,
			wantStatus:      LeakageStatusVerifiedNoLeakage,
			wantVerified:    true,
			wantProven:      true,
			wantEnforced:    true,
			wantChecks:      []string{"id_overlap_check", "source_separation_check"},
			wantMethod:      "manifest:explicit_ids",
			wantReasonParts: []string{"verified: explicit disjoint train/validation IDs with source provenance"},
		},
		{
			name: "leakage_result_sets_enforced_and_overlap_count",
			ver: LeakageVerification{
				Status:          LeakageStatusLeakageDetected,
				LeakageDetected: true,
				OverlapCount:    2,
				OverlapIDs:      []string{"a", "b"},
				Checks:          []string{"id_overlap_check"},
				Summary:         "leakage detected: overlapping record IDs",
			},
			wantStatus:       LeakageStatusLeakageDetected,
			wantEnforced:     true,
			wantOverlapCount: mfIntPtr(2),
			wantChecks:       []string{"id_overlap_check"},
			wantMethod:       "id_overlap_check",
			wantReasonParts:  []string{"leakage detected: overlapping record IDs"},
		},
		{
			name: "unverified_result_is_not_proven_or_enforced",
			ver: LeakageVerification{
				Status:  LeakageStatusUnverified,
				Reasons: []string{"manifest split definition missing"},
				Summary: "unverified: split definition missing",
			},
			wantStatus:      LeakageStatusUnverified,
			wantReasonParts: []string{"unverified: split definition missing", "manifest split definition missing"},
		},
		{
			name: "existing_guard_fields_are_merged_and_preserved",
			guard: &LeakageGuard{
				Enforced:           true,
				Checks:             []string{"id_overlap_check", "old_check"},
				Reason:             "old reason",
				Method:             "existing-method",
				ManifestPath:       "/data/manifest.json",
				ManifestSchema:     DatasetManifestSchemaVersion,
				ManifestKind:       ManifestKindBacktestPairs,
				VerificationSource: "manifest",
			},
			ver:              verifiedVer,
			wantStatus:       LeakageStatusVerifiedNoLeakage,
			wantVerified:     true,
			wantProven:       true,
			wantEnforced:     true,
			wantChecks:       []string{"id_overlap_check", "old_check", "source_separation_check"},
			wantMethod:       "existing-method",
			wantReasonParts:  []string{"old reason", "verified: explicit disjoint train/validation IDs with source provenance"},
			wantPreserveMeta: true,
		},
		{
			name: "zero_overlap_with_leakage_flag_still_records_zero",
			ver: LeakageVerification{
				Status:          LeakageStatusLeakageDetected,
				LeakageDetected: true,
			},
			wantStatus:       LeakageStatusLeakageDetected,
			wantEnforced:     true,
			wantOverlapCount: mfIntPtr(0),
			wantReasonParts:  []string{"verification result unavailable"},
		},
		{
			name: "method_falls_back_to_joined_checks",
			ver: LeakageVerification{
				Status:   LeakageStatusUnverified,
				Checks:   []string{"a", "b"},
				Manifest: &DatasetManifest{Split: &ManifestSplit{}},
			},
			wantStatus:      LeakageStatusUnverified,
			wantChecks:      []string{"a", "b"},
			wantMethod:      "a,b",
			wantReasonParts: []string{"verification result unavailable"},
		},
		{
			name:            "empty_verification_gets_fallback_reason",
			ver:             LeakageVerification{},
			wantReasonParts: []string{"verification result unavailable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: copy metadata so we can prove unrelated fields survive the mapping.
			var before LeakageGuard
			if tt.guard != nil {
				before = *tt.guard
			}

			// Act.
			got := ApplyLeakageVerification(tt.guard, tt.ver)

			if got == nil {
				t.Fatal("ApplyLeakageVerification must return a non-nil guard")
			}
			if tt.guard != nil && got != tt.guard {
				t.Fatal("ApplyLeakageVerification must reuse the provided guard pointer")
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.Verified != tt.wantVerified {
				t.Fatalf("verified = %v, want %v", got.Verified, tt.wantVerified)
			}
			if got.Proven != tt.wantProven {
				t.Fatalf("proven = %v, want %v (status=%q)", got.Proven, tt.wantProven, got.Status)
			}
			if got.Enforced != tt.wantEnforced {
				t.Fatalf("enforced = %v, want %v (status=%q)", got.Enforced, tt.wantEnforced, got.Status)
			}
			if tt.wantOverlapCount == nil {
				if got.OverlapCount != nil {
					t.Fatalf("overlap_count = %v, want nil", *got.OverlapCount)
				}
			} else if got.OverlapCount == nil || *got.OverlapCount != *tt.wantOverlapCount {
				t.Fatalf("overlap_count = %v, want %d", got.OverlapCount, *tt.wantOverlapCount)
			}
			if !reflect.DeepEqual(got.Checks, tt.wantChecks) {
				t.Fatalf("checks = %v, want %v", got.Checks, tt.wantChecks)
			}
			if got.Method != tt.wantMethod {
				t.Fatalf("method = %q, want %q", got.Method, tt.wantMethod)
			}
			for _, part := range tt.wantReasonParts {
				if !strings.Contains(got.Reason, part) {
					t.Fatalf("reason %q does not contain %q", got.Reason, part)
				}
			}
			if tt.wantPreserveMeta {
				if got.ManifestPath != before.ManifestPath || got.ManifestSchema != before.ManifestSchema ||
					got.ManifestKind != before.ManifestKind || got.VerificationSource != before.VerificationSource {
					t.Fatalf("manifest metadata was not preserved: got %+v, before %+v", got, before)
				}
			}
		})
	}
}

// TestNormalizeDoesNotMutateCaller guards the normalized-copy contract:
// DatasetManifest arrives by value but Datasets is a slice and Split holds
// pointers, so normalizing ID lists must not rewrite the caller's nested data.
func TestNormalizeDoesNotMutateCaller(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: DatasetManifestSchemaVersion,
		Kind:          ManifestKindBacktestPairs,
		Datasets: []ManifestDataset{{
			RecordIDs: []string{" b ", "a", "b", ""},
		}},
		Split: &ManifestSplit{
			Train:      &SplitPartition{RecordIDs: []string{" 2 ", "1", "2"}},
			Validation: &SplitPartition{RecordIDs: []string{" 4 ", "3", "4"}},
		},
	}
	origDataset := append([]string(nil), m.Datasets[0].RecordIDs...)
	origTrain := append([]string(nil), m.Split.Train.RecordIDs...)
	origVal := append([]string(nil), m.Split.Validation.RecordIDs...)

	got, err := normalizeAndValidateManifest(m)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !reflect.DeepEqual(got.Datasets[0].RecordIDs, []string{"b", "a"}) {
		t.Fatalf("normalized dataset IDs = %v, want [b a]", got.Datasets[0].RecordIDs)
	}
	if !reflect.DeepEqual(m.Datasets[0].RecordIDs, origDataset) ||
		!reflect.DeepEqual(m.Split.Train.RecordIDs, origTrain) ||
		!reflect.DeepEqual(m.Split.Validation.RecordIDs, origVal) {
		t.Fatalf("caller data was mutated: dataset=%v train=%v val=%v", m.Datasets[0].RecordIDs, m.Split.Train.RecordIDs, m.Split.Validation.RecordIDs)
	}
}

// TestApplyLeakageVerificationKeepsReasonWithoutSummary guards the audit-trail
// context: strings.Contains(s, "") is always true, so an empty verification
// summary used to silently drop a reason already present on the guard.
func TestApplyLeakageVerificationKeepsReasonWithoutSummary(t *testing.T) {
	lg := &LeakageGuard{Reason: "operator flagged suspicious overlap in ticket SEC-9"}
	ver := LeakageVerification{
		Status:  LeakageStatusUnverified,
		Reasons: []string{"insufficient provenance"},
		// Summary intentionally empty.
	}
	got := ApplyLeakageVerification(lg, ver)
	if !strings.Contains(got.Reason, "SEC-9") {
		t.Fatalf("existing reason was dropped when summary is empty: %q", got.Reason)
	}
	if !strings.Contains(got.Reason, "insufficient provenance") {
		t.Fatalf("new verification reason missing: %q", got.Reason)
	}
}
