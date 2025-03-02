// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package libaudit

import (
	"bufio"
	"container/heap"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/go-libaudit/v2/auparse"
)

type testStream struct {
	events  [][]*auparse.AuditMessage
	dropped int
}

func (s *testStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	s.events = append(s.events, msgs)
}

func (s *testStream) EventsLost(count int) { s.dropped += count }

func TestReassembler(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		testReassembler(t, "testdata/normal.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("lost_messages", func(t *testing.T) {
		testReassembler(t, "testdata/lost_messages.log", &results{
			dropped: 9,
			events: []eventMeta{
				{seq: 49, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("out_of_order", func(t *testing.T) {
		testReassembler(t, "testdata/out_of_order.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 58, count: 2},
				{seq: 59, count: 5},
				{seq: 60, count: 5},
				{seq: 61, count: 4},
				{seq: 62, count: 1},
			},
		})
	})

	t.Run("rollover", func(t *testing.T) {
		testReassembler(t, "testdata/rollover.log", &results{
			dropped: 0,
			events: []eventMeta{
				{seq: 4294967294, count: 1},
				{seq: 4294967295, count: 1},
				{seq: 0, count: 1},
				{seq: 1, count: 1},
				{seq: 2, count: 1},
			},
		})
	})
}

type eventMeta struct {
	seq   uint
	count int
}

type results struct {
	dropped    int
	outOfOrder int
	events     []eventMeta
}

func testReassembler(t testing.TB, file string, expected *results) {
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stream := &testStream{events: make([][]*auparse.AuditMessage, 0, 10)}
	reassmbler, err := NewReassembler(5, 2*time.Second, stream)
	if err != nil {
		t.Fatal(err)
	}

	// Read logs and parse events.
	s := bufio.NewScanner(bufio.NewReader(f))
	for s.Scan() {
		line := s.Text()
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			t.Log("invalid message:", line)
			continue
		}

		reassmbler.PushMessage(msg)
	}

	// Flush any pending messages.
	if err := reassmbler.Close(); err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, expected.dropped, stream.dropped, "dropped messages")
	for i, expectedEvent := range expected.events {
		if len(stream.events) <= i {
			t.Fatal("less events received than expected")
		}

		for _, msg := range stream.events[i] {
			assert.EqualValues(t, expectedEvent.seq, msg.Sequence, "sequence number")
		}
		assert.Equal(t, expectedEvent.count, len(stream.events[i]), "message count")
	}
}

func Benchmark_eventList_put(b *testing.B) {
	const maxSize = 10
	h := &intHeap{}
	heap.Init(h)
	eventList := &eventList{
		seqs:    h,
		events:  make(map[int]*event, maxSize+1),
		maxSize: maxSize,
	}
	rand.Seed(time.Now().Unix())

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var msgType auparse.AuditMessageType
		if i%2 == 0 {
			msgType = auparse.AUDIT_EOE
		}
		eventList.Put(&auparse.AuditMessage{
			Sequence:   rand.Uint32(),
			RecordType: msgType,
		})
	}
}

func generateEvents() *eventList {
	const maxSize = 10
	h := &intHeap{}
	heap.Init(h)
	eventList := &eventList{
		seqs:    h,
		events:  make(map[int]*event, maxSize+1),
		maxSize: maxSize,
	}

	for i := 0; i < 100; i++ {
		var msgType auparse.AuditMessageType
		if i%2 == 0 {
			msgType = auparse.AUDIT_EOE
		}
		eventList.Put(&auparse.AuditMessage{
			Sequence:   rand.Uint32(),
			RecordType: msgType,
		})
	}

	return eventList
}

func Benchmark_eventList_cleanup(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		eventList := generateEvents()
		b.StartTimer()
		eventList.CleanUp()
	}
}
