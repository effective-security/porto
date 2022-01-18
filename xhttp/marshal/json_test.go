package marshal

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ShouldPrettyPrint(t *testing.T) {
	f := func(url string, expPP PrettyPrintSetting) {
		r, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		assert.Equal(t, expPP, shouldPrettyPrint(r), "shouldPrettyPrint(%v)", url)
	}
	f("/?pp", PrettyPrint)
	f("/?pp=1", PrettyPrint)
	f("/?pp=true", PrettyPrint)
	f("/", DontPrettyPrint)
	f("/pp", DontPrettyPrint) // not in the query
}

func Test_PrettyPrint(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/?pp", nil)
	require.NoError(t, err)
	assert.Equal(t, PrettyPrint, shouldPrettyPrint(r))
	w := bytes.Buffer{}
	v := map[string]string{"a": "a", "b": "b"}
	err = NewEncoder(&w, r).Encode(v)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":"a", "b":"b"}`, w.String())
	assert.True(t, strings.Contains(w.String(), "\t"))
	assert.True(t, strings.Contains(w.String(), "\n"))
}

type AStruct struct {
	A string
	B string
}

func Test_DecodeJSONRawMessageMakesCopy(t *testing.T) {
	// verifies that go-codec calls json.RawMessage Unmarshal, which
	// in turns makes a copy of the supplied data.
	j := []byte(`{"A":"B"}`)
	r := map[string]*json.RawMessage{}
	assert.NoError(t, DecodeBytes(j, &r))
	assert.Equal(t, json.RawMessage([]byte(`"B"`)), *r["A"])
	j[6] = 'C'
	assert.Equal(t, json.RawMessage([]byte(`"B"`)), *r["A"])
	assert.NoError(t, DecodeBytes(j, &r))
	assert.Equal(t, json.RawMessage([]byte(`"C"`)), *r["A"])
}

func Test_Decode(t *testing.T) {
	j := []byte(`{"A":"a","B":"b","C":"c"}`)
	var r AStruct
	err := Decode(bytes.NewReader(j), &r)
	assert.Error(t, err)
	assert.Equal(t, "json decode error [pos 21]: no matching struct field found when decoding stream map with key C", err.Error())
}

func Test_DecodeBody(t *testing.T) {
	j := []byte(`{"C":"c", "D":false}`)
	w := httptest.NewRecorder()

	r, _ := http.NewRequest(http.MethodPost, "/v1/test", bytes.NewReader(j))
	var resGood map[string]string
	err := DecodeBody(w, r, &resGood)
	require.NoError(t, err)
	assert.Len(t, resGood, 2)

	r, _ = http.NewRequest(http.MethodPost, "/v1/test", bytes.NewReader(j))
	w = httptest.NewRecorder()
	var res AStruct
	err = DecodeBody(w, r, &res)
	require.Error(t, err)
	assert.Equal(t, "json decode error [pos 5]: no matching struct field found when decoding stream map with key C", err.Error())
	assert.Equal(t, `{"code":"invalid_json","message":"failed to decode '*marshal.AStruct': json decode error [pos 5]: no matching struct field found when decoding stream map with key C"}`,
		w.Body.String())
}

func Test_Uint64(t *testing.T) {
	x := []uint64{0, 1000, 65535, 4000000, 4000000000, math.MaxInt32, math.MaxUint32, math.MaxInt64, math.MaxUint64 - 1, math.MaxUint64}
	val := map[string]uint64{"x": 0}

	for _, tv := range x {
		val["x"] = tv
		enc, err := EncodeBytes(DontPrettyPrint, val)
		assert.NoError(t, err, "failed to encode value %d to json", tv)
		t.Logf("encoded %d is %s", tv, enc)

		var decoded map[string]uint64
		err = DecodeBytes(enc, &decoded)
		assert.NoError(t, err, "failed to decode %s back to a map", enc)
		assert.Equal(t, tv, decoded["x"], "uint64 value %d round tripped lost value (encoded was %s)", tv, enc)

		assert.Equal(t, -1, bytes.IndexByte(enc, 'e'), "Unexpected use of scienctific notation in uint64 serialization for value %d: %s", tv, enc)
	}
}
