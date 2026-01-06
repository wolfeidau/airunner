package wal

import "sync"

// walIndex tracks record status in-memory
type walIndex struct {
	mu      sync.RWMutex
	records map[int64]*indexEntry
}

type indexEntry struct {
	sequence int64
	offset   int64
	status   uint8
}

// newWalIndex creates new index
func newWalIndex() *walIndex {
	return &walIndex{
		records: make(map[int64]*indexEntry),
	}
}

// addRecord adds or updates a record entry
func (idx *walIndex) addRecord(sequence, offset int64, status uint8) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.records[sequence] = &indexEntry{
		sequence: sequence,
		offset:   offset,
		status:   status,
	}
}

// getRecord retrieves a record entry
func (idx *walIndex) getRecord(sequence int64) *indexEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	return idx.records[sequence]
}

// markSent marks a record as sent
func (idx *walIndex) markSent(sequence int64) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if entry, ok := idx.records[sequence]; ok {
		entry.status = RecordSent
	}
}

// getUnsent returns all unsent records in sequence order
func (idx *walIndex) getUnsent() []*walRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var unsent []*walRecord
	for _, entry := range idx.records {
		if entry.status == RecordPending || entry.status == RecordFailed {
			unsent = append(unsent, &walRecord{
				sequence: entry.sequence,
				offset:   entry.offset,
				status:   entry.status,
			})
		}
	}

	// Sort by sequence
	sortRecords(unsent)
	return unsent
}

// getAll returns all records
func (idx *walIndex) getAll() []*walRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var all []*walRecord
	for _, entry := range idx.records {
		all = append(all, &walRecord{
			sequence: entry.sequence,
			offset:   entry.offset,
			status:   entry.status,
		})
	}

	// Sort by sequence
	sortRecords(all)
	return all
}

// count returns number of records
func (idx *walIndex) count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	return len(idx.records)
}

// countByStatus returns count of records with given status
func (idx *walIndex) countByStatus(status uint8) int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	count := 0
	for _, entry := range idx.records {
		if entry.status == status {
			count++
		}
	}
	return count
}

// sortRecords sorts records by sequence number
func sortRecords(records []*walRecord) {
	for i := range records {
		for j := i + 1; j < len(records); j++ {
			if records[j].sequence < records[i].sequence {
				records[i], records[j] = records[j], records[i]
			}
		}
	}
}
