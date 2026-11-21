package twin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Dataset manifest schema/version for validation/backtest provenance.
const (
	DatasetManifestSchemaVersion = "sift.twin-dataset-manifest/v1"
	ManifestKindBacktestPairs    = "backtest_pairs"
	ManifestKindValidateCompare  = "validate_compare"

	LeakageStatusVerifiedNoLeakage = "verified_no_leakage"
	LeakageStatusLeakageDetected   = "leakage_detected"
	LeakageStatusUnverified        = "unverified"
)

// ManifestDataset identifies a dataset source with provenance.
type ManifestDataset struct {
	ID            string   `json:"id,omitempty"`
	Kind          string   `json:"kind,omitempty"` // pairs_file|report_file|result_file|manifest
	Path          string   `json:"path,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
	RecordCount   int      `json:"record_count,omitempty"`
	RecordIDs     []string `json:"record_ids,omitempty"` // explicit stable IDs (e.g. indices "0","1" or external IDs)
	MetricScope   string   `json:"metric_scope,omitempty"`
	TimeStart     string   `json:"time_start,omitempty"`
	TimeEnd       string   `json:"time_end,omitempty"`
	Order         string   `json:"order,omitempty"` // e.g. time_asc, index_asc
	Notes         string   `json:"notes,omitempty"`
	PairedWith    string   `json:"paired_with,omitempty"` // for paired predicted/actual datasets
	PredictedPath string   `json:"predicted_path,omitempty"`
	ActualPath    string   `json:"actual_path,omitempty"`
}

// SplitPartition describes one side of a split with explicit refs/IDs.
type SplitPartition struct {
	DatasetID string   `json:"dataset_id,omitempty"`
	Path      string   `json:"path,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
	RecordIDs []string `json:"record_ids,omitempty"` // stable IDs belonging to this partition
	Count     int      `json:"count,omitempty"`
	TimeStart string   `json:"time_start,omitempty"`
	TimeEnd   string   `json:"time_end,omitempty"`
	Notes     string   `json:"notes,omitempty"`
}

// ManifestSplit defines train/validation separation explicitly.
type ManifestSplit struct {
	Strategy           string          `json:"strategy,omitempty"` // explicit_ids|time_cutoff|ratio_holdout|separate_files|unknown
	Train              *SplitPartition `json:"train,omitempty"`
	Validation         *SplitPartition `json:"validation,omitempty"`
	TrainEnd           string          `json:"train_end,omitempty"`
	ValidationStart    string          `json:"validation_start,omitempty"`
	BoundaryOrderField string          `json:"boundary_order_field,omitempty"` // e.g. time,index
	Notes              string          `json:"notes,omitempty"`
}

// DatasetManifest is a canonical dataset/split manifest for validation/backtest.
type DatasetManifest struct {
	SchemaVersion string            `json:"schema_version"`
	Kind          string            `json:"kind"` // backtest_pairs|validate_compare
	CreatedAt     string            `json:"created_at,omitempty"`
	Datasets      []ManifestDataset `json:"datasets,omitempty"`
	Split         *ManifestSplit    `json:"split,omitempty"`
	MetricScope   string            `json:"metric_scope,omitempty"`
	Notes         []string          `json:"notes,omitempty"`
}

// LeakageVerification is the result of provenance-based separation verification.
type LeakageVerification struct {
	Status          string           `json:"status"` // verified_no_leakage|leakage_detected|unverified
	Verified        bool             `json:"verified"`
	LeakageDetected bool             `json:"leakage_detected"`
	OverlapCount    int              `json:"overlap_count"`
	OverlapIDs      []string         `json:"overlap_ids,omitempty"`
	Checks          []string         `json:"checks,omitempty"`
	Reasons         []string         `json:"reasons,omitempty"`
	Manifest        *DatasetManifest `json:"manifest,omitempty"`
	Summary         string           `json:"summary,omitempty"`
}

// WriteManifest writes a manifest as canonical JSON.
func WriteManifest(path string, m DatasetManifest) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("twin: manifest path is required")
	}
	nm, err := normalizeAndValidateManifest(m)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0o750); err != nil {
		return "", fmt.Errorf("twin: create manifest dir: %w", err)
	}
	data, err := json.MarshalIndent(nm, "", "  ")
	if err != nil {
		return "", fmt.Errorf("twin: encode manifest: %w", err)
	}
	clean := filepath.Clean(path)
	if err := atomicWriteFile(clean, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("twin: write manifest %s: %w", clean, err)
	}
	return clean, nil
}

// LoadManifest loads and validates a dataset manifest.
func LoadManifest(path string) (DatasetManifest, error) {
	clean := filepath.Clean(path)
	b, err := os.ReadFile(clean) // #nosec G304 -- operator-selected manifest artifact
	if err != nil {
		return DatasetManifest{}, fmt.Errorf("twin: read manifest %s: %w", clean, err)
	}
	var m DatasetManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return DatasetManifest{}, fmt.Errorf("twin: parse manifest %s: %w", clean, err)
	}
	nm, err := normalizeAndValidateManifest(m)
	if err != nil {
		return DatasetManifest{}, fmt.Errorf("twin: invalid manifest %s: %w", clean, err)
	}
	return nm, nil
}

// ValidateManifest validates a manifest and returns a normalized copy.
func ValidateManifest(m DatasetManifest) (DatasetManifest, error) {
	return normalizeAndValidateManifest(m)
}

func normalizeAndValidateManifest(m DatasetManifest) (DatasetManifest, error) {
	if strings.TrimSpace(m.SchemaVersion) == "" {
		m.SchemaVersion = DatasetManifestSchemaVersion
	}
	if m.SchemaVersion != DatasetManifestSchemaVersion {
		return DatasetManifest{}, fmt.Errorf("twin: unsupported manifest schema %q (want %q)", m.SchemaVersion, DatasetManifestSchemaVersion)
	}
	switch strings.TrimSpace(m.Kind) {
	case ManifestKindBacktestPairs, ManifestKindValidateCompare:
		m.Kind = strings.TrimSpace(m.Kind)
	default:
		return DatasetManifest{}, fmt.Errorf("twin: manifest kind must be %q or %q", ManifestKindBacktestPairs, ManifestKindValidateCompare)
	}
	if strings.TrimSpace(m.CreatedAt) == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Normalize IDs slices (trim/dedupe stable order for comparisons where appropriate)
	for i := range m.Datasets {
		m.Datasets[i].RecordIDs = normalizeIDList(m.Datasets[i].RecordIDs)
	}
	if m.Split != nil {
		if m.Split.Train != nil {
			m.Split.Train.RecordIDs = normalizeIDList(m.Split.Train.RecordIDs)
		}
		if m.Split.Validation != nil {
			m.Split.Validation.RecordIDs = normalizeIDList(m.Split.Validation.RecordIDs)
		}
	}
	return m, nil
}

func normalizeIDList(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// CreateBacktestPairsManifest creates a canonical manifest for pair-array backtest data.
// trainIDs and validationIDs must be explicit stable record IDs (e.g. "0","1"... indices)
// to enable provenance-based separation verification.
func CreateBacktestPairsManifest(pairsPath string, trainIDs, validationIDs []string, strategy string, opts BacktestManifestOptions) (DatasetManifest, error) {
	if strings.TrimSpace(strategy) == "" {
		strategy = "explicit_ids"
	}
	ds := ManifestDataset{Kind: "pairs_file", Path: strings.TrimSpace(pairsPath)}
	if ds.Path != "" {
		if abs, err := filepath.Abs(ds.Path); err == nil {
			ds.Path = abs
		}
		if h, err := hashFileSHA256(ds.Path); err == nil {
			ds.SHA256 = h
		}
	}
	ds.ID = opts.DatasetID
	if ds.ID == "" && ds.Path != "" {
		ds.ID = filepath.Base(ds.Path)
	}
	ds.RecordCount = opts.RecordCount
	ds.MetricScope = opts.MetricScope
	ds.TimeStart = opts.TimeStart
	ds.TimeEnd = opts.TimeEnd
	ds.Order = opts.Order
	ds.PredictedPath = opts.PredictedPath
	ds.ActualPath = opts.ActualPath
	if len(trainIDs) == 0 && len(validationIDs) == 0 && opts.RecordCount > 0 && strings.EqualFold(strategy, "index_order_split") && opts.ValidationStartIndex >= 0 {
		// convenience: generate index IDs
		for i := 0; i < opts.ValidationStartIndex && i < opts.RecordCount; i++ {
			trainIDs = append(trainIDs, fmt.Sprintf("%d", i))
		}
		for i := opts.ValidationStartIndex; i < opts.RecordCount; i++ {
			validationIDs = append(validationIDs, fmt.Sprintf("%d", i))
		}
	}
	split := &ManifestSplit{
		Strategy:           strategy,
		Train:              &SplitPartition{DatasetID: ds.ID, Path: ds.Path, SHA256: ds.SHA256, RecordIDs: normalizeIDList(trainIDs), Count: len(normalizeIDList(trainIDs)), TimeEnd: opts.TrainEnd},
		Validation:         &SplitPartition{DatasetID: ds.ID, Path: ds.Path, SHA256: ds.SHA256, RecordIDs: normalizeIDList(validationIDs), Count: len(normalizeIDList(validationIDs)), TimeStart: opts.ValidationStart},
		TrainEnd:           opts.TrainEnd,
		ValidationStart:    opts.ValidationStart,
		BoundaryOrderField: opts.BoundaryOrderField,
		Notes:              opts.SplitNotes,
	}
	m := DatasetManifest{
		SchemaVersion: DatasetManifestSchemaVersion,
		Kind:          ManifestKindBacktestPairs,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Datasets:      []ManifestDataset{ds},
		Split:         split,
		MetricScope:   opts.MetricScope,
		Notes:         opts.Notes,
	}
	return normalizeAndValidateManifest(m)
}

// BacktestManifestOptions provides optional provenance metadata for manifest creation.
type BacktestManifestOptions struct {
	DatasetID            string
	RecordCount          int
	MetricScope          string
	TimeStart            string
	TimeEnd              string
	Order                string
	PredictedPath        string
	ActualPath           string
	TrainEnd             string
	ValidationStart      string
	BoundaryOrderField   string
	ValidationStartIndex int
	SplitNotes           string
	Notes                []string
}

// CreateValidateCompareManifest creates a canonical manifest for report/result-based validation.
func CreateValidateCompareManifest(actualReportPath, resultOrModelPath string, opts ValidateManifestOptions) (DatasetManifest, error) {
	strategy := strings.TrimSpace(opts.Strategy)
	if strategy == "" {
		strategy = "separate_files"
	}
	datasets := []ManifestDataset{}
	addFile := func(kind, path, id string) ManifestDataset {
		d := ManifestDataset{Kind: kind, Path: strings.TrimSpace(path), ID: id}
		if d.Path != "" {
			if abs, err := filepath.Abs(d.Path); err == nil {
				d.Path = abs
			}
			if h, err := hashFileSHA256(d.Path); err == nil {
				d.SHA256 = h
			}
		}
		if d.ID == "" && d.Path != "" {
			d.ID = filepath.Base(d.Path)
		}
		return d
	}
	trainDS := addFile(opts.TrainKind, opts.TrainPath, opts.TrainID)
	valDS := addFile("actual_report", actualReportPath, opts.ValidationID)
	if trainDS.Path == "" && strings.TrimSpace(resultOrModelPath) != "" {
		trainDS = addFile(ternaryStr(opts.TrainKind != "", opts.TrainKind, "prediction_or_model"), resultOrModelPath, opts.TrainID)
	}
	if trainDS.ID != "" || trainDS.Path != "" || trainDS.SHA256 != "" {
		datasets = append(datasets, trainDS)
	}
	if valDS.ID != "" || valDS.Path != "" || valDS.SHA256 != "" {
		datasets = append(datasets, valDS)
	}
	trainPart := &SplitPartition{DatasetID: trainDS.ID, Path: trainDS.Path, SHA256: trainDS.SHA256, RecordIDs: normalizeIDList(opts.TrainRecordIDs), Count: opts.TrainCount, TimeEnd: opts.TrainEnd}
	valPart := &SplitPartition{DatasetID: valDS.ID, Path: valDS.Path, SHA256: valDS.SHA256, RecordIDs: normalizeIDList(opts.ValidationRecordIDs), Count: opts.ValidationCount, TimeStart: opts.ValidationStart}
	if len(trainPart.RecordIDs) == 0 && trainPart.DatasetID != "" {
		trainPart.RecordIDs = []string{trainPart.DatasetID}
		trainPart.Count = 1
	}
	if len(valPart.RecordIDs) == 0 && valPart.DatasetID != "" {
		valPart.RecordIDs = []string{valPart.DatasetID}
		valPart.Count = 1
	}
	split := &ManifestSplit{Strategy: strategy, Train: trainPart, Validation: valPart, TrainEnd: opts.TrainEnd, ValidationStart: opts.ValidationStart, BoundaryOrderField: opts.BoundaryOrderField, Notes: opts.SplitNotes}
	m := DatasetManifest{SchemaVersion: DatasetManifestSchemaVersion, Kind: ManifestKindValidateCompare, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Datasets: datasets, Split: split, MetricScope: opts.MetricScope, Notes: opts.Notes}
	return normalizeAndValidateManifest(m)
}

// ValidateManifestOptions provides options for validate/compare manifest creation.
type ValidateManifestOptions struct {
	Strategy            string
	TrainPath           string
	TrainKind           string
	TrainID             string
	TrainRecordIDs      []string
	TrainCount          int
	ValidationID        string
	ValidationRecordIDs []string
	ValidationCount     int
	TrainEnd            string
	ValidationStart     string
	BoundaryOrderField  string
	MetricScope         string
	SplitNotes          string
	Notes               []string
}

// VerifyManifestSeparation verifies train/validation separation from manifest provenance.
// It never fabricates verification; insufficient provenance yields UNVERIFIED.
func VerifyManifestSeparation(m DatasetManifest) LeakageVerification {
	res := LeakageVerification{Status: LeakageStatusUnverified, Manifest: &m}
	if m.Split == nil {
		res.Reasons = append(res.Reasons, "manifest split definition missing")
		res.Summary = "unverified: split definition missing"
		return res
	}
	train := m.Split.Train
	val := m.Split.Validation
	if train == nil || val == nil {
		res.Reasons = append(res.Reasons, "manifest split must define both train and validation partitions")
		res.Summary = "unverified: incomplete split partitions"
		return res
	}
	hasTrainProv := hasPartitionProvenance(train)
	hasValProv := hasPartitionProvenance(val)
	if !hasTrainProv || !hasValProv {
		if !hasTrainProv {
			res.Reasons = append(res.Reasons, "train partition lacks sufficient provenance (IDs/hash/path)")
		}
		if !hasValProv {
			res.Reasons = append(res.Reasons, "validation partition lacks sufficient provenance (IDs/hash/path)")
		}
		res.Summary = "unverified: insufficient partition provenance"
		return res
	}

	// ID overlap check when explicit IDs exist on both sides.
	trainIDs := nonEmptyIDs(train.RecordIDs)
	valIDs := nonEmptyIDs(val.RecordIDs)
	if len(trainIDs) > 0 && len(valIDs) > 0 {
		res.Checks = append(res.Checks, "id_overlap_check")
		overlap := intersectIDs(trainIDs, valIDs)
		res.OverlapCount = len(overlap)
		res.OverlapIDs = overlap
		if len(overlap) > 0 {
			res.Status = LeakageStatusLeakageDetected
			res.LeakageDetected = true
			res.Reasons = append(res.Reasons, fmt.Sprintf("train/validation ID overlap detected (%d IDs)", len(overlap)))
			res.Summary = "leakage detected: overlapping record IDs"
			return res
		}
		res.Reasons = append(res.Reasons, fmt.Sprintf("no ID overlap detected across %d train and %d validation IDs", len(trainIDs), len(valIDs)))
	}

	// Same-file/same-hash partition without disjoint IDs cannot be verified as separated.
	sameSource := false
	if train.SHA256 != "" && val.SHA256 != "" && strings.EqualFold(train.SHA256, val.SHA256) {
		sameSource = true
		res.Checks = append(res.Checks, "hash_equality_check")
	} else if train.Path != "" && val.Path != "" && filepath.Clean(train.Path) == filepath.Clean(val.Path) {
		sameSource = true
		res.Checks = append(res.Checks, "path_equality_check")
	} else if train.DatasetID != "" && val.DatasetID != "" && train.DatasetID == val.DatasetID {
		sameSource = true
		res.Checks = append(res.Checks, "dataset_id_equality_check")
	}

	if sameSource && (len(trainIDs) == 0 || len(valIDs) == 0) {
		res.Reasons = append(res.Reasons, "train/validation reference same source but explicit disjoint record IDs are missing")
		res.Summary = "unverified: same source without explicit ID-level separation"
		return res
	}

	// Time/boundary check for time-ordered strategies when metadata provided.
	if isTimeOrderedStrategy(m.Split.Strategy) || (strings.TrimSpace(m.Split.TrainEnd) != "" && strings.TrimSpace(m.Split.ValidationStart) != "") {
		res.Checks = append(res.Checks, "time_boundary_check")
		trainEnd := firstNonEmpty(train.TimeEnd, m.Split.TrainEnd)
		valStart := firstNonEmpty(val.TimeStart, m.Split.ValidationStart)
		te, teErr := parseManifestTime(trainEnd)
		vs, vsErr := parseManifestTime(valStart)
		if teErr != nil || vsErr != nil || trainEnd == "" || valStart == "" {
			// If strategy claims time ordering but boundaries unparseable/missing and no ID proof, cannot verify.
			if sameSource && (len(trainIDs) == 0 || len(valIDs) == 0) {
				res.Reasons = append(res.Reasons, "time-ordered split boundaries missing/unparseable and ID-level separation unavailable")
				res.Summary = "unverified: time boundary cannot be proven"
				return res
			}
			if len(trainIDs) == 0 || len(valIDs) == 0 {
				res.Reasons = append(res.Reasons, "time boundary metadata incomplete/unparseable; cannot prove separation without explicit IDs")
				res.Summary = "unverified: insufficient boundary evidence"
				return res
			}
			res.Reasons = append(res.Reasons, "time boundary metadata incomplete/unparseable but explicit disjoint ID sets provided")
		} else {
			if te.After(vs) {
				res.Status = LeakageStatusLeakageDetected
				res.LeakageDetected = true
				res.OverlapCount = maxInt(res.OverlapCount, 1)
				res.Reasons = append(res.Reasons, fmt.Sprintf("time boundary overlap: train_end %s is after validation_start %s", te.Format(time.RFC3339Nano), vs.Format(time.RFC3339Nano)))
				res.Summary = "leakage detected: overlapping time boundary"
				return res
			}
			res.Reasons = append(res.Reasons, fmt.Sprintf("time boundary OK: train_end %s <= validation_start %s", te.Format(time.RFC3339Nano), vs.Format(time.RFC3339Nano)))
		}
	}

	// If different sources and provenance present, require either disjoint IDs (for same logical dataset class) or strong separate-source evidence.
	differentSources := !sameSource && (train.SHA256 != "" || train.Path != "" || train.DatasetID != "") && (val.SHA256 != "" || val.Path != "" || val.DatasetID != "")
	if differentSources {
		res.Checks = append(res.Checks, "source_separation_check")
		// Different files/hashes/IDs are strong evidence when strategy is separate_files/explicit or when IDs known disjoint.
		if len(trainIDs) > 0 && len(valIDs) > 0 {
			// overlap already checked
			res.Status = LeakageStatusVerifiedNoLeakage
			res.Verified = true
			res.Summary = "verified: explicit disjoint train/validation IDs with source provenance"
			return res
		}
		if isSeparateSourceStrategy(m.Split.Strategy) {
			res.Status = LeakageStatusVerifiedNoLeakage
			res.Verified = true
			res.Reasons = append(res.Reasons, "train and validation reference different dataset sources with provenance; treated as separated for this split strategy")
			res.Summary = "verified: separate train/validation dataset sources"
			return res
		}
		// different sources but unknown relationship and no IDs -> unverified
		res.Reasons = append(res.Reasons, "different dataset sources provided but explicit record-ID separation not proven and strategy is ambiguous")
		res.Summary = "unverified: source separation not provable without IDs/strategy evidence"
		return res
	}

	// Same source but disjoint explicit IDs and no boundary violation.
	if sameSource && len(trainIDs) > 0 && len(valIDs) > 0 {
		res.Status = LeakageStatusVerifiedNoLeakage
		res.Verified = true
		res.Summary = "verified: explicit disjoint train/validation record IDs"
		return res
	}

	res.Summary = "unverified: insufficient evidence to prove separation"
	if len(res.Reasons) == 0 {
		res.Reasons = append(res.Reasons, "no verifiable separation proof available from provided manifest/provenance")
	}
	return res
}

func hasPartitionProvenance(p *SplitPartition) bool {
	if p == nil {
		return false
	}
	if len(nonEmptyIDs(p.RecordIDs)) > 0 {
		return true
	}
	if strings.TrimSpace(p.SHA256) != "" || strings.TrimSpace(p.Path) != "" || strings.TrimSpace(p.DatasetID) != "" {
		return true
	}
	return false
}

func nonEmptyIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

func intersectIDs(a, b []string) []string {
	set := map[string]bool{}
	for _, id := range a {
		set[id] = true
	}
	var overlap []string
	seen := map[string]bool{}
	for _, id := range b {
		if set[id] && !seen[id] {
			seen[id] = true
			overlap = append(overlap, id)
		}
	}
	sort.Strings(overlap)
	return overlap
}

func isTimeOrderedStrategy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Contains(s, "time") || strings.Contains(s, "temporal") || strings.Contains(s, "chron")
}

func isSeparateSourceStrategy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "separate_files" || s == "explicit_datasets" || s == "separate_datasets" || s == "external_split"
}

func parseManifestTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable time")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func hashFileSHA256(path string) (string, error) {
	clean := filepath.Clean(path)
	f, err := os.Open(clean) // #nosec G304 -- operator-selected local file for provenance hashing
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashBytesSHA256 returns hex SHA-256 digest for content.
func HashBytesSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputeBacktestManifestFromInput builds a manifest for backtest pairs input.
// If split IDs are not provided, it can infer index-based IDs but only verifies
// separation when explicit train/validation ID sets or separate sources are provided.
func ComputeBacktestManifestFromInput(inputPath string, predicted, actual []float64, split *SplitSpec, dataset *DatasetRef) (DatasetManifest, LeakageVerification, error) {
	// A pairs file may carry different numbers of predictions and actuals.
	// Provenance records the paired minimum; BacktestErrors is the strict
	// consumer and withholds metrics unless the two slices have equal length,
	// so mismatched input is intentionally not rejected here.
	n := len(predicted)
	if len(actual) < n {
		n = len(actual)
	}
	opts := BacktestManifestOptions{RecordCount: n}
	if dataset != nil {
		opts.DatasetID = dataset.ID
		opts.MetricScope = ""
		opts.TimeStart = dataset.TimeStart
		opts.TimeEnd = dataset.TimeEnd
	}
	strategy := "unknown"
	var trainIDs, valIDs []string
	trainEnd, valStart := "", ""
	boundaryField := ""
	splitNotes := ""
	if split != nil {
		strategy = strings.TrimSpace(split.Strategy)
		trainEnd = split.TrainEnd
		valStart = split.ValidationStart
		splitNotes = split.Notes
		trainIDs = append(trainIDs, split.TrainIDs...)
		valIDs = append(valIDs, split.ValidationIDs...)
		boundaryField = split.BoundaryOrderField
		// support boundary index hints encoded in notes is unreliable; prefer explicit IDs
	}
	if strings.TrimSpace(strategy) == "" {
		strategy = "unknown"
	}
	m, err := CreateBacktestPairsManifest(inputPath, trainIDs, valIDs, strategy, opts)
	if err != nil {
		return DatasetManifest{}, LeakageVerification{}, err
	}
	if m.Split != nil {
		m.Split.TrainEnd = trainEnd
		m.Split.ValidationStart = valStart
		m.Split.BoundaryOrderField = boundaryField
		if splitNotes != "" {
			m.Split.Notes = splitNotes
		}
	}
	m, err = normalizeAndValidateManifest(m)
	if err != nil {
		return DatasetManifest{}, LeakageVerification{}, fmt.Errorf("twin: normalize computed backtest manifest: %w", err)
	}
	ver := VerifyManifestSeparation(m)
	return m, ver, nil
}

// ApplyLeakageVerification maps verification result into LeakageGuard fields (additive).
func ApplyLeakageVerification(lg *LeakageGuard, ver LeakageVerification) *LeakageGuard {
	if lg == nil {
		lg = &LeakageGuard{}
	}
	lg.Status = ver.Status
	lg.Verified = ver.Verified
	lg.Proven = ver.Verified && ver.Status == LeakageStatusVerifiedNoLeakage
	lg.Enforced = lg.Enforced || ver.Verified || ver.LeakageDetected
	if ver.OverlapCount > 0 || ver.LeakageDetected {
		oc := ver.OverlapCount
		lg.OverlapCount = &oc
	}
	if len(ver.Checks) > 0 {
		lg.Checks = uniqueStrings(append(append([]string{}, lg.Checks...), ver.Checks...))
	}
	if strings.TrimSpace(lg.Method) == "" {
		if ver.Manifest != nil && ver.Manifest.Split != nil && strings.TrimSpace(ver.Manifest.Split.Strategy) != "" {
			lg.Method = "manifest:" + ver.Manifest.Split.Strategy
		} else if len(ver.Checks) > 0 {
			lg.Method = strings.Join(ver.Checks, ",")
		}
	}
	reasonParts := []string{}
	if strings.TrimSpace(ver.Summary) != "" {
		reasonParts = append(reasonParts, ver.Summary)
	}
	reasonParts = append(reasonParts, ver.Reasons...)
	if len(reasonParts) > 0 {
		// keep explicit context but don't drop existing reason entirely
		if strings.TrimSpace(lg.Reason) != "" && !strings.Contains(lg.Reason, ver.Summary) {
			reasonParts = append([]string{lg.Reason}, reasonParts...)
		}
		lg.Reason = strings.Join(uniqueStrings(reasonParts), "; ")
	}
	if lg.Reason == "" {
		lg.Reason = "verification result unavailable"
	}
	return lg
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
