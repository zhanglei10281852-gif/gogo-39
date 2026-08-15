package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"agentguard/model"
)

func TestCanonicalJSONStableAndStrict(t *testing.T) {
	first, err := Canonicalize([]byte(` {"z":1.0,"a":{"b":2,"a":"<&"}} `))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Canonicalize([]byte(`{"a":{"a":"<&","b":2.0},"z":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical forms differ:\n%s\n%s", first, second)
	}
	if string(first) != `{"a":{"a":"<&","b":2},"z":1}` {
		t.Fatalf("unexpected canonical JSON: %s", first)
	}
	if _, err := Canonicalize([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate object member was accepted")
	}
}

func openTestLedger(t *testing.T) *Ledger {
	t.Helper()
	ledger, err := New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}
func TestAppendVerifyQueryStatisticsCheckpointAndTransfer(t *testing.T) {
	ledger := openTestLedger(t)
	ctx := context.Background()
	base := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	for i, kind := range []string{"decision", "access", "decision"} {
		_, err := ledger.Append(ctx, EventInput{
			Timestamp: base.Add(time.Duration(i) * time.Second), Type: kind,
			ActorID: fmt.Sprintf("actor-%d", i%2), PolicyID: "policy",
			Payload: map[string]any{"index": i, "nested": map[string]any{"ok": true}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	report, err := ledger.Verify(ctx)
	if err != nil || !report.Valid || report.Events != 3 {
		t.Fatalf("verify = %+v, %v", report, err)
	}
	events, err := ledger.Query(ctx, Query{Types: []string{"decision"}, Reverse: true, Limit: 1})
	if err != nil || len(events) != 1 || events[0].Sequence != 3 {
		t.Fatalf("query = %+v, %v", events, err)
	}
	stats, err := ledger.Statistics(ctx, Query{})
	if err != nil || stats.Total != 3 || stats.ByType["decision"] != 2 || stats.ByActor["actor-0"] != 2 {
		t.Fatalf("statistics = %+v, %v", stats, err)
	}
	checkpoint, err := ledger.CreateCheckpoint(ctx)
	if err != nil || ledger.VerifyCheckpoint(ctx, checkpoint) != nil {
		t.Fatalf("checkpoint = %+v, %v", checkpoint, err)
	}
	if _, err := ledger.Append(ctx, EventInput{Type: "later", Payload: nil}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.VerifyCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("historical checkpoint failed after append: %v", err)
	}
	var exported bytes.Buffer
	if err := ledger.Export(ctx, &exported); err != nil {
		t.Fatal(err)
	}
	imported := openTestLedger(t)
	if err := imported.Import(ctx, bytes.NewReader(exported.Bytes())); err != nil {
		t.Fatal(err)
	}
	importReport, err := imported.Verify(ctx)
	if err != nil || importReport.Events != 4 || importReport.LastHash != reportHash(t, ledger) {
		t.Fatalf("import verify = %+v, %v", importReport, err)
	}
}

func reportHash(t *testing.T, ledger *Ledger) string {
	t.Helper()
	report, err := ledger.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return report.LastHash
}
func TestTamperDetectionAndTailRepair(t *testing.T) {
	ledger := openTestLedger(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := ledger.Append(ctx, EventInput{Type: "event", Payload: map[string]int{"n": i}}); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.OpenFile(ledger.Path(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(`{"incomplete":`)
	_ = file.Close()
	if report, err := ledger.Verify(ctx); err == nil || report.Valid {
		t.Fatalf("invalid tail not detected: %+v, %v", report, err)
	}
	// Corrupt ledgers remain openable for explicit verification and repair.
	reopened, err := New(ledger.Path())
	if err != nil {
		t.Fatalf("reopen corrupt ledger: %v", err)
	}
	repaired, err := reopened.RepairTail(ctx)
	if err != nil || !repaired.Valid || repaired.Events != 2 {
		t.Fatalf("repair = %+v, %v", repaired, err)
	}
	data, err := os.ReadFile(ledger.Path())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	var first map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	first["type"] = "tampered"
	changed, _ := json.Marshal(first)
	bad := append(changed, '\n')
	bad = append(bad, lines[1]...)
	bad = append(bad, '\n')
	if err := os.WriteFile(ledger.Path(), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RepairTail(ctx); !errors.Is(err, ErrNotTail) {
		t.Fatalf("middle corruption repair error = %v, want ErrNotTail", err)
	}
}

func TestConcurrentIndependentLedgersSerializeWithLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.jsonl")
	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 10
	const perWorker = 12
	var group sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			selected := first
			if worker%2 == 1 {
				selected = second
			}
			for item := 0; item < perWorker; item++ {
				_, err := selected.Append(context.Background(), EventInput{
					Type: "concurrent", Payload: map[string]int{"worker": worker, "item": item},
				})
				if err != nil {
					errorsChannel <- err
					return
				}
			}
		}(worker)
	}
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	report, err := first.Verify(context.Background())
	if err != nil || report.Events != workers*perWorker || report.LastSequence != workers*perWorker {
		t.Fatalf("concurrent report = %+v, %v", report, err)
	}
}
func TestReplayAndSafeFileStore(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"../escape.jsonl", `..\\escape.jsonl`, "/absolute.jsonl", "sub/file.jsonl"} {
		if _, err := store.Open(unsafe); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Open(%q) error = %v, want ErrUnsafePath", unsafe, err)
		}
	}
	ledger, err := store.Open("replay.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	request := model.EvaluationRequest{RequestID: "request-1"}
	recorded := model.DecisionResult{
		RequestID: "request-1", Decision: model.DecisionAllow, Risk: model.RiskLow,
		Reasons: []string{"stable"}, Fingerprint: "fingerprint-a",
	}
	if _, err := ledger.Append(context.Background(), EventInput{
		Type: "decision", RequestID: request.RequestID,
		Payload: ReplayRecord{Request: request, Result: recorded},
	}); err != nil {
		t.Fatal(err)
	}
	matched, err := ledger.Replay(context.Background(), "", func(_ context.Context, got model.EvaluationRequest) (model.DecisionResult, error) {
		if got.RequestID != request.RequestID {
			t.Fatalf("unexpected replay request: %+v", got)
		}
		return recorded, nil
	})
	if err != nil || matched.Examined != 1 || matched.Matched != 1 || len(matched.Mismatches) != 0 {
		t.Fatalf("matched replay = %+v, %v", matched, err)
	}
	mismatch, err := ledger.Replay(context.Background(), "decision", func(context.Context, model.EvaluationRequest) (model.DecisionResult, error) {
		changed := recorded
		changed.Fingerprint = "fingerprint-b"
		return changed, nil
	})
	if err != nil || mismatch.Matched != 0 || len(mismatch.Mismatches) != 1 {
		t.Fatalf("mismatch replay = %+v, %v", mismatch, err)
	}
	names, err := store.LedgerNames()
	if err != nil || len(names) != 1 || names[0] != "replay.jsonl" {
		t.Fatalf("ledger names = %v, %v", names, err)
	}
}
