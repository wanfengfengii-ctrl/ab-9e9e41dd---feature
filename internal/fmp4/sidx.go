package fmp4

// sidxInfo is the parsed content of a segment index box (ISO/IEC 14496-12
// 8.16.3). Versions 0 and 1 are accepted.
type sidxInfo struct {
	timescale uint32
	earliest  uint64 // earliest_presentation_time
	firstOff  uint64 // first_offset
	refs      []sidxReference
}

type sidxReference struct {
	referencedSize uint32 // bytes of the referenced moof/mdat extent
	duration       uint32 // subsegment_duration in the sidx timescale
}

// parseSidx parses and structurally validates one sidx box. Semantic checks
// (timescale equality, offsets and timing against the actual fragment) are the
// caller's job.
func parseSidx(b *box, seg, frag int) (*sidxInfo, *AuditError) {
	version, flags, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return nil, aerr
	}
	if version > 1 || flags != 0 {
		return nil, errf(CodeBoxStructureInvalid, seg, frag,
			"sidx has unsupported version=%d flags=0x%06x", version, flags)
	}
	c := &cursor{b: body}
	if _, ok := c.u32(); !ok { // reference_ID
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx truncated at reference_ID")
	}
	ts, ok := c.u32()
	if !ok {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx truncated at timescale")
	}
	if ts == 0 {
		return nil, errf(CodeSidxTimescaleInvalid, seg, frag, "sidx timescale is zero")
	}
	var earliest, firstOff uint64
	switch version {
	case 0:
		e32, ok1 := c.u32()
		o32, ok2 := c.u32()
		if !ok1 || !ok2 {
			return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx v0 truncated at earliest_presentation_time/first_offset")
		}
		earliest, firstOff = uint64(e32), uint64(o32)
	case 1:
		var ok1, ok2 bool
		earliest, ok1 = c.u64()
		firstOff, ok2 = c.u64()
		if !ok1 || !ok2 {
			return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx v1 truncated at earliest_presentation_time/first_offset")
		}
	default:
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "unsupported sidx version %d", version)
	}
	if !c.skip(2) { // reserved
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx truncated at reserved word")
	}
	count16, ok := c.u16()
	if !ok {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx truncated at reference_count")
	}
	if count16 != 1 {
		return nil, errf(CodeSidxReferenceCount, seg, frag,
			"sidx contains %d media reference(s), expected exactly 1", count16)
	}

	// One reference: reference_type(1) + referenced_size(3),
	// subsegment_duration(4), SAP type(1)/delta_time(3)/SAP(1..3)/total(4).
	head := make([]byte, 4)
	if !c.read(head) {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "sidx reference truncated")
	}
	if head[0] != 0 {
		return nil, errf(CodeSidxReferenceCount, seg, frag,
			"sidx reference has reference_type %d, expected 0 (media content)", head[0])
	}
	refSize := uint32(head[1])<<16 | uint32(head[2])<<8 | uint32(head[3])
	dur, ok := c.u32()
	if !ok {
		return nil, errf(CodeBoxStructureInvalid, seg, frag,
			"sidx reference truncated at subsegment_duration")
	}
	if !c.skip(4) { // SAP signalling
		return nil, errf(CodeBoxStructureInvalid, seg, frag,
			"sidx reference truncated at SAP signalling")
	}
	if c.off != len(body) {
		return nil, errf(CodeBoxStructureInvalid, seg, frag,
			"sidx has %d trailing byte(s) after its single reference", len(body)-c.off)
	}

	return &sidxInfo{
		timescale: ts,
		earliest:  uint64(earliest),
		firstOff:  uint64(firstOff),
		refs:      []sidxReference{{referencedSize: refSize, duration: dur}},
	}, nil
}

// checkSIDX enforces that one media part carries exactly one top-level sidx
// whose single media reference precisely describes the part's moof/mdat bytes
// and decode interval. On success it records the declared index metadata on
// the part's first fragment.
func checkSIDX(tops []box, init *initTrack, frags []fragment, seg, fragBase int) *AuditError {
	sidxs := findBoxes(tops, "sidx")
	if len(sidxs) == 0 {
		return errf(CodeMissingSidx, seg, fragBase,
			"media segment %d has no top-level sidx box", seg)
	}
	if len(sidxs) > 1 {
		return errf(CodeMultipleSidx, seg, fragBase,
			"media segment %d has %d top-level sidx boxes, expected exactly 1", seg, len(sidxs))
	}
	sidx := &sidxs[0]
	si, aerr := parseSidx(sidx, seg, fragBase)
	if aerr != nil {
		return aerr
	}
	if si.timescale != init.timescale {
		return errf(CodeSidxTimescaleInvalid, seg, fragBase,
			"sidx timescale %d does not match the audio track timescale %d",
			si.timescale, init.timescale)
	}
	if si.firstOff != 0 {
		return errf(CodeSidxFirstOffset, seg, fragBase,
			"sidx first_offset is %d, expected 0 (reference starts right after the sidx)",
			si.firstOff)
	}

	// Locate the sidx among the top-level boxes (by offset). Every box before
	// it must be non-media (typically styp), and every box after it must be
	// exactly the referenced moof/mdat extent with nothing trailing.
	sidxAt := -1
	for i := range tops {
		if tops[i].start == sidx.start {
			sidxAt = i
			break
		}
	}
	if sidxAt < 0 {
		return errf(CodeBoxStructureInvalid, seg, fragBase, "sidx is not a top-level box")
	}
	for _, b := range tops[:sidxAt+1] {
		if b.typ == "moof" || b.typ == "mdat" {
			return errf(CodeSidxRangeMismatch, seg, fragBase,
				"media segment %d has a %s box before its sidx; the index must precede the media it references",
				seg, b.typ)
		}
	}
	var wantSize int64
	for _, b := range tops[sidxAt+1:] {
		if b.typ != "moof" && b.typ != "mdat" {
			return errf(CodeSidxRangeMismatch, seg, fragBase,
				"sidx reference covers a trailing %q box that is not moof/mdat", b.typ)
		}
		wantSize += b.size
	}
	rangeStart := sidx.start + sidx.size + int64(si.firstOff)
	if sidxAt+1 >= len(tops) || tops[sidxAt+1].start != rangeStart {
		return errf(CodeSidxRangeMismatch, seg, fragBase,
			"sidx reference starts at byte %d but the moof/mdat bytes start at %d",
			rangeStart, tops[sidxAt+1].start)
	}
	if uint64(wantSize) != uint64(si.refs[0].referencedSize) {
		return errf(CodeSidxRangeMismatch, seg, fragBase,
			"sidx reference covers %d byte(s) but the moof/mdat boxes after it span %d byte(s)",
			si.refs[0].referencedSize, wantSize)
	}

	// Timing: the single reference must describe this part's whole decode
	// interval: earliest presentation time and summed sample duration.
	wantStart := frags[0].start
	var wantDuration uint64
	for _, f := range frags {
		wantDuration += f.duration
	}
	if si.earliest != wantStart {
		return errf(CodeSidxTimeMismatch, seg, fragBase,
			"sidx earliest_presentation_time is %d but the part decodes from tick %d",
			si.earliest, wantStart)
	}
	if uint64(si.refs[0].duration) != wantDuration {
		return errf(CodeSidxDurationMismatch, seg, fragBase,
			"sidx subsegment_duration is %d tick(s) but the part decodes for %d tick(s)",
			si.refs[0].duration, wantDuration)
	}

	frags[0].indexStart = si.earliest
	frags[0].indexDuration = uint64(si.refs[0].duration)
	frags[0].indexReferencedBytes = uint64(si.refs[0].referencedSize)
	return nil
}
