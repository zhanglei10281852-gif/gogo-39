package filestore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrInvalidPath identifies empty, absolute, or traversal paths.
	ErrInvalidPath = errors.New("invalid store path")
	// ErrPathEscape identifies a path that could resolve outside the root.
	ErrPathEscape = errors.New("store path escapes root")
	// ErrSymlink identifies a symbolic link in a store path.
	ErrSymlink = errors.New("symbolic links are not allowed in store paths")
)

// cleanRelative validates a caller-supplied store path without normalizing
// away evidence of traversal.
func cleanRelative(name string) (string, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("%w: path is empty or contains NUL", ErrInvalidPath)
	}
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: absolute path %q", ErrInvalidPath, name)
	}
	for _, component := range strings.FieldsFunc(name, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if component == ".." {
			return "", fmt.Errorf("%w: parent traversal in %q", ErrInvalidPath, name)
		}
	}
	cleaned := filepath.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path has no file name or traverses", ErrInvalidPath)
	}
	return cleaned, nil
}

func (s *Store) resolve(name string) (string, error) {
	if err := s.checkReady(); err != nil {
		return "", err
	}
	relative, err := cleanRelative(name)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(s.root, relative)
	inside, err := filepath.Rel(s.root, candidate)
	if err != nil {
		return "", fmt.Errorf("compare path to root: %w", err)
	}
	if inside == "." || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
		return "", fmt.Errorf("%w: %q", ErrPathEscape, name)
	}
	return candidate, nil
}

func (s *Store) verifyRoot() error {
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("inspect store root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: store root", ErrSymlink)
	}
	if !info.IsDir() {
		return fmt.Errorf("store root is not a directory")
	}
	return nil
}

// verifyPath rejects symlinks in every existing component below the root.
// allowMissing permits a missing final path or missing intermediate directory.
func (s *Store) verifyPath(path string, allowMissing bool) error {
	if err := s.verifyRoot(); err != nil {
		return err
	}
	relative, err := filepath.Rel(s.root, path)
	if err != nil {
		return fmt.Errorf("compare path to root: %w", err)
	}
	if relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q", ErrPathEscape, path)
	}
	current := s.root
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) && allowMissing {
				return nil
			}
			return fmt.Errorf("inspect path component %q: %w", part, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: component %q", ErrSymlink, part)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("path component %q is not a directory", part)
		}
	}
	return nil
}

// secureParent creates absent parent directories one component at a time and
// verifies every component with Lstat. Newly-created directories are private.
func (s *Store) secureParent(path string) (string, error) {
	if err := s.verifyRoot(); err != nil {
		return "", err
	}
	parent := filepath.Dir(path)
	relative, err := filepath.Rel(s.root, parent)
	if err != nil {
		return "", fmt.Errorf("compare parent to root: %w", err)
	}
	if relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: parent of %q", ErrPathEscape, path)
	}
	if relative == "." {
		return s.root, nil
	}
	current := s.root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				return "", fmt.Errorf("create directory %q: %w", part, mkdirErr)
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect directory %q: %w", part, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: directory %q", ErrSymlink, part)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("path component %q is not a directory", part)
		}
	}
	return parent, nil
}

// openVerifiedRead opens a regular file only after checking its path, then
// compares the open handle with a fresh Lstat result to detect replacement.
func (s *Store) openVerifiedRead(path string) (*os.File, os.FileInfo, error) {
	if err := s.verifyPath(path, false); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("stat open file: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("reinspect open file: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		file.Close()
		return nil, nil, fmt.Errorf("%w: final file", ErrSymlink)
	}
	if !os.SameFile(openedInfo, pathInfo) {
		file.Close()
		return nil, nil, fmt.Errorf("file changed while opening")
	}
	if !openedInfo.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("store path is not a regular file")
	}
	return file, openedInfo, nil
}
