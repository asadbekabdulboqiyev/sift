package dashboard

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/asadbekabdulboqiyev/sift/internal/bounty"
)

func copyFileTo(src, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- src is an internal path previously saved within the request-scoped temp directory.
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(in, bounty.MaxArtifactBytes+1))
	if err != nil {
		return err
	}
	if n > bounty.MaxArtifactBytes {
		return fmt.Errorf("file exceeds %d byte limit", bounty.MaxArtifactBytes)
	}
	return nil
}

func readUploadedText(r *http.Request, field string) string {
	fhs := r.MultipartForm.File[field]
	if len(fhs) == 0 {
		return ""
	}
	f, err := fhs[0].Open()
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readUploadedFileByName(r *http.Request, name string) string {
	for _, fhs := range r.MultipartForm.File {
		for _, fh := range fhs {
			if fh == nil || filepath.Base(fh.Filename) != name {
				continue
			}
			f, err := fh.Open()
			if err != nil {
				return ""
			}
			b, err := io.ReadAll(io.LimitReader(f, 4<<20))
			_ = f.Close()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func sanitizeUploadPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.ToSlash(filepath.Clean(name))
	name = strings.TrimPrefix(name, "/")
	if name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return filepath.Base(name)
	}
	// keep relative subpaths; verifier will reject unsafe ones too
	return name
}

func saveMultipartFile(fh *multipart.FileHeader, baseDir, dst string) error {
	base := filepath.Clean(baseDir)
	cleanDst := filepath.Clean(dst)
	rel, err := filepath.Rel(base, cleanDst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes temp directory")
	}
	if err := os.MkdirAll(filepath.Dir(cleanDst), 0o700); err != nil {
		return err
	}
	src, err := fh.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.OpenFile(cleanDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(src, bounty.MaxArtifactBytes+1))
	if err != nil {
		return err
	}
	if n > bounty.MaxArtifactBytes {
		return fmt.Errorf("file exceeds %d byte limit", bounty.MaxArtifactBytes)
	}
	return nil
}
