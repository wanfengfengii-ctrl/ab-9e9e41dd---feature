package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"fmp4audit/internal/fixture"
)

func buildMultipart(t *testing.T, init []byte, segs ...[]byte) (body *bytes.Buffer, contentType string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	write := func(name, filename string, data []byte) {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, name, filename))
		h.Set("Content-Type", "application/octet-stream")
		pw, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("init", "init.mp4", init)
	for i, s := range segs {
		write("segment", fmt.Sprintf("segment-%d.m4s", i+1), s)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf, mw.FormDataContentType()
}

func post(t *testing.T, target string, body *bytes.Buffer, contentType string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, parsed
}

func goodInit() []byte {
	return fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
}

func goodSeg(seq uint32, tm uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: tm, Samples: fixture.Samples(3, 1024, 16),
	})
}

func errorCode(t *testing.T, resp map[string]any) string {
	t.Helper()
	e, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error object in %v", resp)
	}
	code, _ := e["code"].(string)
	return code
}

func TestHandlerOK(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 3072))
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if resp["ok"] != true {
		t.Fatalf("ok=%v", resp["ok"])
	}
	if resp["totalDuration"] != 6144.0 {
		t.Fatalf("totalDuration=%v", resp["totalDuration"])
	}
	frags, ok := resp["fragments"].([]any)
	if !ok || len(frags) != 2 {
		t.Fatalf("fragments=%v", resp["fragments"])
	}
}

func TestHandlerGap(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 4096))
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "TIMELINE_GAP" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 1.0 || e["segmentIndex"] != 1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/fmp4/audit", nil)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandlerBadContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/fmp4/audit", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandlerNoMediaSegments(t *testing.T) {
	body, ct := buildMultipart(t, goodInit())
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "NO_MEDIA_SEGMENTS" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerTooManySegments(t *testing.T) {
	segs := make([][]byte, 33)
	for i := range segs {
		segs[i] = goodSeg(uint32(i+1), uint64(i*3072))
	}
	body, ct := buildMultipart(t, goodInit(), segs...)
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "TOO_MANY_SEGMENTS" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerPayloadTooLarge(t *testing.T) {
	big := make([]byte, maxTotalBytes) // init alone hits the 16 MiB limit
	body, ct := buildMultipart(t, big, goodSeg(1, 0))
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func goodSidxSeg(seq uint32, tm uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: tm, Samples: fixture.Samples(3, 1024, 16), Sidx: true,
	})
}

func TestHandlerIndexSidxOK(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSidxSeg(1, 0), goodSidxSeg(2, 3072))
	status, resp := post(t, "/api/fmp4/audit?index=sidx", body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	segs, ok := resp["segments"].([]any)
	if !ok || len(segs) != 2 {
		t.Fatalf("segments=%v", resp["segments"])
	}
	first := segs[0].(map[string]any)
	if first["index"] != 0.0 || first["indexStart"] != 0.0 ||
		first["indexDuration"] != 3072.0 || first["referencedBytes"].(float64) <= 0 {
		t.Fatalf("segment 0 = %v", first)
	}
	second := segs[1].(map[string]any)
	if second["index"] != 1.0 || second["indexStart"] != 3072.0 ||
		second["indexDuration"] != 3072.0 {
		t.Fatalf("segment 1 = %v", second)
	}
}

func TestHandlerLegacyOmitsSegments(t *testing.T) {
	// sidx-carrying segments audited without the query parameter: accepted
	// as before, and the response carries no segments field.
	body, ct := buildMultipart(t, goodInit(), goodSidxSeg(1, 0))
	status, resp := post(t, "/api/fmp4/audit", body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if _, present := resp["segments"]; present {
		t.Fatalf("legacy response carries segments: %v", resp["segments"])
	}
}

func TestHandlerBadIndexMode(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSidxSeg(1, 0))
	status, resp := post(t, "/api/fmp4/audit?index=smix", body, ct)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "BAD_INDEX_MODE" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["segmentIndex"] != -1.0 || e["fragmentIndex"] != -1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerIndexSidxMissing(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSidxSeg(1, 0), goodSeg(2, 3072))
	status, resp := post(t, "/api/fmp4/audit?index=sidx", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "MISSING_SIDX" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["segmentIndex"] != 1.0 || e["fragmentIndex"] != -1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerIndexSidxRangeMismatch(t *testing.T) {
	small := uint32(8)
	bad := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: true, SidxRefSize: &small,
	})
	body, ct := buildMultipart(t, goodInit(), bad)
	status, resp := post(t, "/api/fmp4/audit?index=sidx", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "SIDX_RANGE_MISMATCH" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerIndexSidxTimeMismatch(t *testing.T) {
	dur := uint32(4096)
	bad := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Sidx: true, SidxDuration: &dur,
	})
	body, ct := buildMultipart(t, goodInit(), bad)
	status, resp := post(t, "/api/fmp4/audit?index=sidx", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "SIDX_TIME_MISMATCH" {
		t.Fatalf("code %q", code)
	}
}
