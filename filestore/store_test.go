package filestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type record struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func newTestStore(t *testing.T, options ...Option) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "store"), options...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func TestRejectsInvalidAndTraversalPaths(t *testing.T) {
	store := newTestStore(t)
	absolute := filepath.Join(filepath.VolumeName(store.Root())+string(filepath.Separator), "escape.json")
	names := []string{"", ".", "..", "../escape.json", "a/../../escape.json", `a\..\escape.json`, absolute}
	for _, name := range names {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			err := store.WriteJSON(name, record{ID: 1})
			if err == nil {
				t.Fatalf("WriteJSON(%q) unexpectedly succeeded", name)
			}
			if !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("WriteJSON(%q) error = %v, want ErrInvalidPath", name, err)
			}
		})
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	store := newTestStore(t)
	outside := t.TempDir()
	link := filepath.Join(store.Root(), "linked")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink privilege unavailable: %v", err)
		}
		t.Fatalf("Symlink: %v", err)
	}
	if err := store.WriteJSON("linked/escape.json", record{ID: 1}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("WriteJSON through symlink error = %v, want ErrSymlink", err)
	}
	if err := store.AppendJSONL("linked/escape.jsonl", record{ID: 1}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("AppendJSONL through symlink error = %v, want ErrSymlink", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "escape.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside file was created or unexpected error: %v", err)
	}
}

func TestWriteJSONAtomicallyReplacesFile(t *testing.T) {
	store := newTestStore(t)
	oldValue := record{ID: 1, Name: strings.Repeat("old", 1000)}
	newValue := record{ID: 2, Name: strings.Repeat("new", 1000)}
	if err := store.WriteJSON("nested/state.json", oldValue); err != nil {
		t.Fatalf("initial WriteJSON: %v", err)
	}
	var (
		oldHandle *os.File
		err       error
	)
	if runtime.GOOS != "windows" {
		oldHandle, err = os.Open(filepath.Join(store.Root(), "nested", "state.json"))
		if err != nil {
			t.Fatalf("open old file: %v", err)
		}
		defer oldHandle.Close()
	}
	if err := store.WriteJSON("nested/state.json", newValue); err != nil {
		t.Fatalf("replacement WriteJSON: %v", err)
	}
	var got record
	if err := store.ReadJSON("nested/state.json", &got); err != nil {
		t.Fatalf("ReadJSON replacement: %v", err)
	}
	if got != newValue {
		t.Fatalf("replacement = %#v, want %#v", got, newValue)
	}
	if oldHandle != nil {
		var oldGot record
		if err := decodeStrictJSON(oldHandle, &oldGot); err != nil {
			t.Fatalf("old open handle became partial/invalid: %v", err)
		}
		if oldGot != oldValue {
			t.Fatalf("old handle = %#v, want old value", oldGot)
		}
	}
	entries, err := os.ReadDir(filepath.Join(store.Root(), "nested"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".filestore-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX mode bits")
	}
	store := newTestStore(t)
	if err := store.WriteJSON("private/data.json", record{ID: 1}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	for path, want := range map[string]os.FileMode{
		store.Root():                                     0o700,
		filepath.Join(store.Root(), "private"):           0o700,
		filepath.Join(store.Root(), "private/data.json"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("mode(%s) = %o, want %o", path, got, want)
		}
	}
}

func TestReadJSONIsStrictAndBounded(t *testing.T) {
	store := newTestStore(t, WithMaxJSONBytes(64))
	path := filepath.Join(store.Root(), "raw.json")
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"id":1,"name":"ok","extra":true}`},
		{name: "trailing value", data: `{"id":1,"name":"ok"} {}`},
		{name: "trailing garbage", data: `{"id":1,"name":"ok"} nope`},
		{name: "oversized", data: `{"id":1,"name":"` + strings.Repeat("x", 80) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			var got record
			if err := store.ReadJSON("raw.json", &got); err == nil {
				t.Fatalf("ReadJSON accepted %s", test.name)
			}
		})
	}
	if err := os.WriteFile(path, []byte(`{"id":7,"name":"valid"}`+"\n\t"), 0o600); err != nil {
		t.Fatalf("WriteFile valid: %v", err)
	}
	var got record
	if err := store.ReadJSON("raw.json", &got); err != nil {
		t.Fatalf("ReadJSON valid: %v", err)
	}
	if got.ID != 7 || got.Name != "valid" {
		t.Fatalf("decoded = %#v", got)
	}
}

func TestJSONLRoundTripAndPointerElements(t *testing.T) {
	store := newTestStore(t)
	want := []record{{ID: 1, Name: "first"}, {ID: 2, Name: "second"}}
	for _, item := range want {
		if err := store.AppendJSONL("events/items.jsonl", item); err != nil {
			t.Fatalf("AppendJSONL: %v", err)
		}
	}
	var values []record
	if err := store.ReadJSONL("events/items.jsonl", &values); err != nil {
		t.Fatalf("ReadJSONL values: %v", err)
	}
	if fmt.Sprint(values) != fmt.Sprint(want) {
		t.Fatalf("values = %#v, want %#v", values, want)
	}
	var pointers []*record
	if err := store.ReadJSONL("events/items.jsonl", &pointers); err != nil {
		t.Fatalf("ReadJSONL pointers: %v", err)
	}
	if len(pointers) != 2 || pointers[0] == nil || *pointers[1] != want[1] {
		t.Fatalf("pointers = %#v", pointers)
	}
}

func TestJSONLReportsLineAndPreservesDestination(t *testing.T) {
	store := newTestStore(t)
	path := filepath.Join(store.Root(), "bad.jsonl")
	data := "{\"id\":1,\"name\":\"ok\"}\n{\"id\":2,\"unknown\":true}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	destination := []record{{ID: 99, Name: "unchanged"}}
	err := store.ReadJSONL("bad.jsonl", &destination)
	var lineError *LineError
	if !errors.As(err, &lineError) {
		t.Fatalf("error = %v, want LineError", err)
	}
	if lineError.Line != 2 {
		t.Fatalf("line = %d, want 2", lineError.Line)
	}
	if len(destination) != 1 || destination[0].ID != 99 {
		t.Fatalf("destination changed on error: %#v", destination)
	}
}

func TestJSONLEmptyMalformedAndLineLimits(t *testing.T) {
	store := newTestStore(t, WithMaxJSONLLineBytes(32), WithMaxJSONLBytes(128))
	path := filepath.Join(store.Root(), "limits.jsonl")
	cases := []struct {
		name string
		data string
		line int
	}{
		{name: "empty", data: "{\"id\":1}\n\n", line: 2},
		{name: "malformed", data: "{\"id\":1}\n{broken}\n", line: 2},
		{name: "long line", data: `{"id":1,"name":"` + strings.Repeat("x", 40) + `"}` + "\n", line: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			var got []record
			err := store.ReadJSONL("limits.jsonl", &got)
			var lineError *LineError
			if !errors.As(err, &lineError) || lineError.Line != test.line {
				t.Fatalf("error = %v, want LineError at %d", err, test.line)
			}
		})
	}
	if err := store.AppendJSONL("append.jsonl", record{Name: strings.Repeat("z", 40)}); err == nil {
		t.Fatal("AppendJSONL accepted an oversized line")
	}
}

func TestConcurrentJSONLAppendIsComplete(t *testing.T) {
	storeA := newTestStore(t)
	storeB, err := New(storeA.Root())
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	const writers = 8
	const perWriter = 20
	var wait sync.WaitGroup
	errorsChannel := make(chan error, writers)
	for writer := 0; writer < writers; writer++ {
		wait.Add(1)
		go func(writer int) {
			defer wait.Done()
			store := storeA
			if writer%2 != 0 {
				store = storeB
			}
			for item := 0; item < perWriter; item++ {
				if err := store.AppendJSONL("concurrent.jsonl", record{ID: writer*1000 + item}); err != nil {
					errorsChannel <- err
					return
				}
			}
		}(writer)
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("AppendJSONL: %v", err)
	}
	var got []record
	if err := storeA.ReadJSONL("concurrent.jsonl", &got); err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(got) != writers*perWriter {
		t.Fatalf("decoded %d records, want %d", len(got), writers*perWriter)
	}
}

func TestRejectsRootReplacedBySymlink(t *testing.T) {
	store := newTestStore(t)
	originalRoot := store.Root()
	movedRoot := originalRoot + "-moved"
	if err := os.Rename(originalRoot, movedRoot); err != nil {
		t.Fatalf("move root: %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, originalRoot); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink privilege unavailable: %v", err)
		}
		t.Fatalf("replace root with symlink: %v", err)
	}
	err := store.WriteJSON("escape.json", record{ID: 1})
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("WriteJSON after root swap error = %v, want ErrSymlink", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "escape.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside file was created or unexpected error: %v", err)
	}
}
