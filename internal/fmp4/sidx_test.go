package fmp4

import (
	"testing"

	"fmp4audit/internal/fixture"
)

func goodSidxSeg(seq uint32, t uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: t, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{},
	})
}

func TestAuditSidxAccepted(t *testing.T) {
	rep, aerr := AuditWithOptions(goodInit(), [][]byte{
		goodSidxSeg(1, 0),
		goodSidxSeg(2, 3072),
		goodSidxSeg(3, 6144),
	}, Options{RequireSIDX: true})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 3 || rep.TotalDuration != 9216 {
		t.Fatalf("fragments=%d total=%d", rep.FragmentCount, rep.TotalDuration)
	}
	for i, f := range rep.Fragments {
		wantStart := uint64(i * 3072)
		if f.IndexStart == nil || *f.IndexStart != wantStart {
			t.Fatalf("fragment %d indexStart=%v, want %d", i, f.IndexStart, wantStart)
		}
		if f.IndexDuration == nil || *f.IndexDuration != 3072 {
			t.Fatalf("fragment %d indexDuration=%v, want 3072", i, f.IndexDuration)
		}
		if f.IndexReferencedBytes == nil || *f.IndexReferencedBytes == 0 {
			t.Fatalf("fragment %d indexReferencedBytes=%v, want > 0", i, f.IndexReferencedBytes)
		}
	}
}

func TestAuditSidxFieldsAbsentInLegacyMode(t *testing.T) {
	rep, aerr := Audit(goodInit(), [][]byte{goodSidxSeg(1, 0)})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	f := rep.Fragments[0]
	if f.IndexStart != nil || f.IndexDuration != nil || f.IndexReferencedBytes != nil {
		t.Fatalf("legacy mode populated index fields: %+v", f)
	}
}

func TestAuditSidxLegacyModeIgnoresMissingSidx(t *testing.T) {
	// Segments without sidx must keep being accepted in legacy mode.
	if _, aerr := Audit(goodInit(), [][]byte{goodSeg(1, 0)}); aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
}

func TestAuditSidxStillEnforcesTimelineGap(t *testing.T) {
	// Per-part sidx checks are additive: an honest index does not excuse a gap.
	expectCodeOpts(t, goodInit(), [][]byte{goodSidxSeg(1, 0), goodSidxSeg(2, 4096)},
		Options{RequireSIDX: true}, CodeTimelineGap, 1, 1)
}

func TestAuditSidxAcceptedV1(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, TfdtV0: false, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{V1: true},
	})
	rep, aerr := AuditWithOptions(goodInit(), [][]byte{seg}, Options{RequireSIDX: true})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.Fragments[0].IndexStart == nil || *rep.Fragments[0].IndexStart != 0 {
		t.Fatalf("fragment: %+v", rep.Fragments[0])
	}
}

func TestAuditSidxMultipleMoofsOneReference(t *testing.T) {
	// One part may hold several moof/mdat pairs behind a single sidx whose one
	// reference spans them all.
	a := goodSeg(1, 0)
	b := goodSeg(2, 3072)
	const stypLen = 24 // fixture styp box is always 24 bytes
	media := catBytes(a[stypLen:], b[stypLen:])
	sidx := fixture.SidxBox(1, 48000, 0, 0, uint32(len(media)), 6144)
	seg := catBytes(a[:stypLen], sidx, media)

	rep, aerr := AuditWithOptions(goodInit(), [][]byte{seg}, Options{RequireSIDX: true})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 2 {
		t.Fatalf("fragments=%d, want 2", rep.FragmentCount)
	}
	f0 := rep.Fragments[0]
	if f0.IndexReferencedBytes == nil || *f0.IndexReferencedBytes != uint64(len(media)) {
		t.Fatalf("referenced bytes=%v, want %d", f0.IndexReferencedBytes, len(media))
	}
	if f0.IndexDuration == nil || *f0.IndexDuration != 6144 {
		t.Fatalf("duration=%v, want 6144", f0.IndexDuration)
	}
}

func catBytes(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestAuditSidxMissing(t *testing.T) {
	expectCodeOpts(t, goodInit(), [][]byte{goodSidxSeg(1, 0), goodSeg(2, 3072)},
		Options{RequireSIDX: true}, CodeMissingSidx, 1, 1)
}

func TestAuditSidxTimescaleMismatch(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{Timescale: 24000},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxTimescaleInvalid, 0, 0)
}

func TestAuditSidxFirstOffset(t *testing.T) {
	off := uint32(12)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{FirstOffset: &off},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxFirstOffset, 0, 0)
}

func TestAuditSidxReferenceCountZero(t *testing.T) {
	n := uint16(0)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{ReferenceCount: &n},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxReferenceCount, 0, 0)
}

func TestAuditSidxReferenceCountTwo(t *testing.T) {
	n := uint16(2)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{ReferenceCount: &n},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxReferenceCount, 0, 0)
}

func TestAuditSidxReferenceTypeIndex(t *testing.T) {
	// reference_type=1 points at another sidx (index reference), not media.
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{ReferenceType: 1},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxReferenceCount, 0, 0)
}

func TestAuditSidxRangeMismatch(t *testing.T) {
	// Claim one fewer referenced byte: the review node would under-read.
	real := sidxReferencedSize(t, goodSidxSeg(1, 0))
	size := real - 1
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{ReferencedSize: &size},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxRangeMismatch, 0, 0)
}

func TestAuditSidxRangeMismatchTrailingBox(t *testing.T) {
	// Extra trailing bytes after the referenced moof/mdat extent.
	seg := append(goodSidxSeg(1, 0), fixture.Box("free", []byte{1, 2, 3, 4})...)
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxRangeMismatch, 0, 0)
}

func TestAuditSidxMultiple(t *testing.T) {
	// A second (dishonest) sidx at the tail must be rejected outright.
	base := goodSidxSeg(1, 0)
	real := sidxReferencedSize(t, base)
	extra := fixture.SidxBox(1, 48000, 0, 0, real, 3072)
	seg := append(base, extra...)
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeMultipleSidx, 0, 0)
}

func TestAuditSidxDurationMismatch(t *testing.T) {
	dur := uint32(2048)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{Duration: &dur},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxDurationMismatch, 0, 0)
}

func TestAuditSidxTimeMismatch(t *testing.T) {
	earliest := uint32(512)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{EarliestTime: &earliest},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg},
		Options{RequireSIDX: true}, CodeSidxTimeMismatch, 0, 0)
}

func TestAuditSidxErrorReportsPartIndex(t *testing.T) {
	// The offending media part's 0-based index must be reported.
	wrong := uint32(1024)
	bad := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 2, BaseTime: 3072, Samples: fixture.Samples(3, 1024, 16),
		Sidx: &fixture.SidxOpts{Duration: &wrong},
	})
	expectCodeOpts(t, goodInit(), [][]byte{goodSidxSeg(1, 0), bad},
		Options{RequireSIDX: true}, CodeSidxDurationMismatch, 1, 1)
}

// expectCodeOpts audits with explicit options and requires the given code.
func expectCodeOpts(t *testing.T, init []byte, segs [][]byte, opts Options, code string, seg, frag int) {
	t.Helper()
	_, aerr := AuditWithOptions(init, segs, opts)
	if aerr == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if aerr.Code != code {
		t.Fatalf("expected %s, got %s (%s)", code, aerr.Code, aerr.Message)
	}
	if aerr.SegmentIndex != seg || aerr.FragmentIndex != frag {
		t.Fatalf("expected indices %d/%d, got %d/%d",
			seg, frag, aerr.SegmentIndex, aerr.FragmentIndex)
	}
}

// sidxReferencedSize extracts the referenced_size field of the first sidx box
// in an honestly built segment.
func sidxReferencedSize(t *testing.T, buf []byte) uint32 {
	t.Helper()
	for i := 0; i+8 <= len(buf); i++ {
		if string(buf[i+4:i+8]) != "sidx" {
			continue
		}
		// full-box header(4) + reference_ID(4) + timescale(4) +
		// earliest(4) + first_offset(4) + reserved/count(4), then the
		// 12-byte reference with size in its first 3 bytes.
		ref := i + 8 + 4 + 4 + 4 + 4 + 4 + 4
		return uint32(buf[ref+1])<<16 | uint32(buf[ref+2])<<8 | uint32(buf[ref+3])
	}
	t.Fatal("no sidx found")
	return 0
}
