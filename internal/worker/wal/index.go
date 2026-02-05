package wal

import "sync"

// walIndex tracks record metadata for the WAL
// Provides fast lookups for unsent/sent/failed records
type walIndex struct {
	mu         sync.RWMutex
	records    []walRecord
	seqToIndex map[int64]int // Maps sequence number to index in records slice
}

// newWALIndex creates a new index
func newWALIndex() *walIndex {
	return &walIndex{
		records:    make([]walRecord, 0, 1000),
		seqToIndex: make(map[int64]int, 1000),
	}
}

// Add adds a record to the index
func (idx *walIndex) Add(rec walRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.seqToIndex[rec.sequence] = len(idx.records)
	idx.records = append(idx.records, rec)
}

// GetUnsent returns all records with status RecordPending
func (idx *walIndex) GetUnsent() []walRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var unsent []walRecord
	for _, rec := range idx.records {
		if rec.status == RecordPending {
			unsent = append(unsent, rec)
		}
	}
	return unsent
}

// MarkSent marks the given records as sent
func (idx *walIndex) MarkSent(recs []walRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Use sequence-to-index map for O(1) lookups
	for _, rec := range recs {
		if i, ok := idx.seqToIndex[rec.sequence]; ok {
			idx.records[i].status = RecordSent
		}
	}
}

// MarkFailed marks the given records as failed
func (idx *walIndex) MarkFailed(recs []walRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Use sequence-to-index map for O(1) lookups
	for _, rec := range recs {
		if i, ok := idx.seqToIndex[rec.sequence]; ok {
			idx.records[i].status = RecordFailed
		}
	}
}

// Count returns the total number of records
func (idx *walIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.records)
}

// CountPending returns the number of pending records
func (idx *walIndex) CountPending() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	count := 0
	for _, rec := range idx.records {
		if rec.status == RecordPending {
			count++
		}
	}
	return count
}

// CountSent returns the number of sent records
func (idx *walIndex) CountSent() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	count := 0
	for _, rec := range idx.records {
		if rec.status == RecordSent {
			count++
		}
	}
	return count
}

// CountFailed returns the number of failed records
func (idx *walIndex) CountFailed() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	count := 0
	for _, rec := range idx.records {
		if rec.status == RecordFailed {
			count++
		}
	}
	return count
}

// GetAll returns all records (for debugging)
func (idx *walIndex) GetAll() []walRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	result := make([]walRecord, len(idx.records))
	copy(result, idx.records)
	return result
}

// GetBySequence returns a record by sequence number
func (idx *walIndex) GetBySequence(sequence int64) (walRecord, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if i, ok := idx.seqToIndex[sequence]; ok {
		return idx.records[i], true
	}
	return walRecord{}, false
}
