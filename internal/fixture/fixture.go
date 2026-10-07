// Package fixture builds synthetic but well-formed fMP4 init and media
// segments for unit tests and HTTP smoke tests.
package fixture

import "encoding/binary"

// Sample is one audio sample's duration (in track timescale ticks) and size
// (in bytes).
type Sample struct {
	Dur  uint32
	Size uint32
}

// Samples returns n identical samples.
func Samples(n int, dur, size uint32) []Sample {
	out := make([]Sample, n)
	for i := range out {
		out[i] = Sample{Dur: dur, Size: size}
	}
	return out
}

func cat(parts ...[]byte) []byte {
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

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// Box wraps a payload in a size/type header.
func Box(typ string, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
	copy(out[4:8], typ)
	return append(out, payload...)
}

func fullBox(typ string, version byte, flags uint32, payload []byte) []byte {
	head := []byte{version, byte(flags >> 16), byte(flags >> 8), byte(flags)}
	return Box(typ, cat(head, payload))
}

// InitOpts configures InitSegment.
type InitOpts struct {
	Timescale    uint32 // default 48000
	TrackID      uint32 // default 1
	Handler      string // default "soun"
	TrexDuration uint32 // trex default_sample_duration
	TrexSize     uint32 // trex default_sample_size
	OmitMvex     bool
	ExtraTracks  int // additional dummy audio tracks
}

// InitSegment builds an fMP4 initialization segment.
func InitSegment(o InitOpts) []byte {
	if o.Timescale == 0 {
		o.Timescale = 48000
	}
	if o.TrackID == 0 {
		o.TrackID = 1
	}
	if o.Handler == "" {
		o.Handler = "soun"
	}

	ftyp := Box("ftyp", cat([]byte("isom"), be32(0), []byte("isomiso6dash")))

	mvhdBody := make([]byte, 96)
	binary.BigEndian.PutUint32(mvhdBody[8:12], 1000)     // timescale
	binary.BigEndian.PutUint32(mvhdBody[12:16], 0x10000) // rate 1.0
	binary.BigEndian.PutUint16(mvhdBody[16:18], 0x0100)  // volume 1.0
	binary.BigEndian.PutUint32(mvhdBody[92:96], 2)       // next_track_ID
	mvhd := fullBox("mvhd", 0, 0, mvhdBody)

	parts := [][]byte{mvhd, buildTrak(o.TrackID, o.Handler, o.Timescale)}
	for i := 0; i < o.ExtraTracks; i++ {
		parts = append(parts, buildTrak(o.TrackID+1+uint32(i), "soun", o.Timescale))
	}
	if !o.OmitMvex {
		trex := fullBox("trex", 0, 0, cat(
			be32(o.TrackID), be32(1), be32(o.TrexDuration), be32(o.TrexSize), be32(0)))
		parts = append(parts, Box("mvex", trex))
	}
	return cat(ftyp, Box("moov", cat(parts...)))
}

func buildTrak(trackID uint32, handler string, timescale uint32) []byte {
	tkhdBody := make([]byte, 80)
	binary.BigEndian.PutUint32(tkhdBody[8:12], trackID)
	binary.BigEndian.PutUint16(tkhdBody[32:34], 0x0100) // volume
	tkhd := fullBox("tkhd", 0, 0x000007, tkhdBody)

	mdhdBody := make([]byte, 24)
	binary.BigEndian.PutUint32(mdhdBody[8:12], timescale)
	mdhd := fullBox("mdhd", 0, 0, mdhdBody)

	hdlr := fullBox("hdlr", 0, 0, cat(
		be32(0), []byte(handler), make([]byte, 12), []byte("SoundHandler\x00")))

	smhd := fullBox("smhd", 0, 0, make([]byte, 4))
	mp4aPayload := make([]byte, 28)
	binary.BigEndian.PutUint16(mp4aPayload[6:8], 1)    // data_reference_index
	binary.BigEndian.PutUint16(mp4aPayload[16:18], 2)  // channelcount
	binary.BigEndian.PutUint16(mp4aPayload[18:20], 16) // samplesize
	binary.BigEndian.PutUint32(mp4aPayload[24:28], 48000<<16)
	stsd := fullBox("stsd", 0, 0, cat(be32(1), Box("mp4a", mp4aPayload)))
	stts := fullBox("stts", 0, 0, be32(0))
	stsc := fullBox("stsc", 0, 0, be32(0))
	stsz := fullBox("stsz", 0, 0, cat(be32(0), be32(0)))
	stco := fullBox("stco", 0, 0, be32(0))
	stbl := Box("stbl", cat(stsd, stts, stsc, stsz, stco))
	minf := Box("minf", cat(smhd, stbl))

	mdia := Box("mdia", cat(mdhd, hdlr, minf))
	return Box("trak", cat(tkhd, mdia))
}

// SidxOpts configures the top-level sidx box that MediaSegment prepends when
// MediaOpts.Sidx is set. The zero value of every *uint32 override means
// "derive the correct value from the segment itself", so an empty SidxOpts
// produces a valid index; the overrides exist to craft malformed indices.
type SidxOpts struct {
	Timescale uint32 // sidx timescale; 0 defaults to 48000

	EarliestTime   *uint32 // override earliest_presentation_time (default: BaseTime)
	FirstOffset    *uint32 // override first_offset (default: 0)
	ReferencedSize *uint32 // override referenced_size (default: moof+mdat bytes)
	Duration       *uint32 // override subsegment_duration (default: sample duration sum)

	ReferenceCount *uint16 // override reference_count (default: one entry)
	ReferenceType  byte    // override the reference_type byte (default: 0 = media)
	V1             bool    // emit a version-1 sidx (64-bit earliest time/offset)
}

// SidxBox builds a version-0 sidx full box with exactly one media reference
// covering referencedSize bytes and duration ticks.
func SidxBox(referenceID, timescale, earliestTime, firstOffset, referencedSize, duration uint32) []byte {
	ref := []byte{
		0x00, // reference_type = 0 (media reference)
		byte(referencedSize >> 16), byte(referencedSize >> 8), byte(referencedSize),
		byte(duration >> 24), byte(duration >> 16), byte(duration >> 8), byte(duration),
		0x80, 0, 0, 0, // starts_with_SAP=1, SAP_type=0, SAP_delta_time=0
	}
	body := cat(
		be32(referenceID),
		be32(timescale),
		be32(earliestTime),
		be32(firstOffset),
		[]byte{0, 0, 0, 1}, // reserved(16b)=0, reference_count(16b)=1
		ref,
	)
	return fullBox("sidx", 0, 0, body)
}

// sidxBoxFor builds the sidx box requested by opts, deriving the honest
// values from the segment's moof/mdat bytes and sample durations.
func sidxBoxFor(o SidxOpts, trackID uint32, baseTime uint64, mediaSize, segDuration uint32) []byte {
	timescale := o.Timescale
	if timescale == 0 {
		timescale = 48000
	}
	var earliest uint64 = baseTime
	var firstOff uint64
	refSize, dur := mediaSize, segDuration
	if o.EarliestTime != nil {
		earliest = uint64(*o.EarliestTime)
	}
	if o.FirstOffset != nil {
		firstOff = uint64(*o.FirstOffset)
	}
	if o.ReferencedSize != nil {
		refSize = *o.ReferencedSize
	}
	if o.Duration != nil {
		dur = *o.Duration
	}

	ref := []byte{
		o.ReferenceType,
		byte(refSize >> 16), byte(refSize >> 8), byte(refSize),
		byte(dur >> 24), byte(dur >> 16), byte(dur >> 8), byte(dur),
		0x80, 0, 0, 0, // starts_with_SAP=1, SAP_type=0, SAP_delta_time=0
	}
	count := uint16(1)
	if o.ReferenceCount != nil {
		count = *o.ReferenceCount
	}
	var times []byte
	if o.V1 {
		times = cat(be64(earliest), be64(firstOff))
	} else {
		times = cat(be32(uint32(earliest)), be32(uint32(firstOff)))
	}
	body := cat(
		be32(trackID),
		be32(timescale),
		times,
		[]byte{0, 0, byte(count >> 8), byte(count)},
		ref,
	)
	version := byte(0)
	if o.V1 {
		version = 1
	}
	return fullBox("sidx", version, 0, body)
}

// MediaOpts configures MediaSegment.
type MediaOpts struct {
	Seq          uint32
	TrackID      uint32 // tfhd track_ID, default 1
	BaseTime     uint64 // tfdt baseMediaDecodeTime
	TfdtV0       bool   // write tfdt version 0 instead of version 1
	Samples      []Sample
	SecondTrun   []Sample // optional second trun in the same traf
	TfhdDefaults bool     // carry duration/size as tfhd defaults, not per-sample
	InheritTrex  bool     // no per-sample values and no tfhd defaults (trex only)

	OmitTfdt bool
	OmitTrun bool
	OmitMdat bool

	MdatPadTail   int    // append this many unreferenced bytes to mdat
	MdatTruncate  int    // shrink mdat payload by this many bytes
	DataOffset    *int32 // explicit data_offset for the first trun
	SecondOverlap uint32 // shift second trun's data_offset back by this many bytes

	// Sidx, when non-nil, prepends a top-level sidx box describing the
	// following moof/mdat extent. An empty SidxOpts is an honest index.
	Sidx *SidxOpts
}

// MediaSegment builds an fMP4 media segment: styp, moof(mfhd, traf(tfhd,
// tfdt, trun...)), mdat.
func MediaSegment(o MediaOpts) []byte {
	if o.TrackID == 0 {
		o.TrackID = 1
	}
	perSample := !o.TfhdDefaults && !o.InheritTrex

	tfhdFlags := uint32(0x020000) // default-base-is-moof
	tfhdBody := be32(o.TrackID)
	if o.TfhdDefaults && len(o.Samples) > 0 {
		tfhdFlags |= 0x000008 | 0x000010
		tfhdBody = cat(tfhdBody, be32(o.Samples[0].Dur), be32(o.Samples[0].Size))
	}
	tfhd := fullBox("tfhd", 0, tfhdFlags, tfhdBody)

	var tfdt []byte
	if !o.OmitTfdt {
		if o.TfdtV0 {
			tfdt = fullBox("tfdt", 0, 0, be32(uint32(o.BaseTime)))
		} else {
			tfdt = fullBox("tfdt", 1, 0, be64(o.BaseTime))
		}
	}

	buildTrun := func(samples []Sample, dataOffset int32) []byte {
		flags := uint32(0x000001) // data-offset-present
		if perSample {
			flags |= 0x000100 | 0x000200
		}
		body := cat(be32(uint32(len(samples))), be32(uint32(dataOffset)))
		if perSample {
			for _, s := range samples {
				body = cat(body, be32(s.Dur), be32(s.Size))
			}
		}
		return fullBox("trun", 0, flags, body)
	}

	mfhd := fullBox("mfhd", 0, 0, be32(o.Seq))
	assemble := func(truns [][]byte) []byte {
		trafParts := append([][]byte{tfhd, tfdt}, truns...)
		return Box("moof", cat(mfhd, Box("traf", cat(trafParts...))))
	}

	var truns [][]byte
	if !o.OmitTrun {
		truns = append(truns, buildTrun(o.Samples, 0))
		if o.SecondTrun != nil {
			truns = append(truns, buildTrun(o.SecondTrun, 0))
		}
	}
	// The trun data_offset is relative to the moof start; the moof length
	// does not depend on the offset values, so compute it once.
	moofLen := int32(len(assemble(truns)))

	if !o.OmitTrun {
		off1 := moofLen + 8 // skip the mdat header
		if o.DataOffset != nil {
			off1 = *o.DataOffset
		}
		truns = [][]byte{buildTrun(o.Samples, off1)}
		if o.SecondTrun != nil {
			off2 := off1 + int32(totalSize(o.Samples)) - int32(o.SecondOverlap)
			truns = append(truns, buildTrun(o.SecondTrun, off2))
		}
	}
	moof := assemble(truns)

	var mdat []byte
	if !o.OmitMdat {
		n := totalSize(o.Samples) + totalSize(o.SecondTrun) + o.MdatPadTail - o.MdatTruncate
		if n < 0 {
			n = 0
		}
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = 0xA5
		}
		mdat = Box("mdat", payload)
	}

	styp := Box("styp", cat([]byte("msdh"), be32(0), []byte("msdhmsix")))
	parts := [][]byte{styp}
	if o.Sidx != nil {
		// mediaSize/duration are the honest values; SidxOpts may override them
		// to craft a mismatching index.
		mediaSize := uint32(len(moof)) + uint32(len(mdat))
		var segDur uint32
		for _, s := range o.Samples {
			segDur += s.Dur
		}
		for _, s := range o.SecondTrun {
			segDur += s.Dur
		}
		parts = append(parts, sidxBoxFor(*o.Sidx, o.TrackID, o.BaseTime, mediaSize, segDur))
	}
	parts = append(parts, moof, mdat)
	return cat(parts...)
}

func totalSize(samples []Sample) int {
	n := 0
	for _, s := range samples {
		n += int(s.Size)
	}
	return n
}
