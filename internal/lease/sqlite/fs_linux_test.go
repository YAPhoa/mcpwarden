//go:build linux

package sqlite

import (
	"strings"
	"testing"
)

func TestFilesystemClassifier(t *testing.T) {
	for magic, want := range map[int64]fsKind{0xef53: fsLocal, 0x01021994: fsLocal, 0x794c7630: fsLocal, 0x6969: fsRemote,
		0x65735546: fsRemote, 0xff534d42: fsRemote, -0x1acb2be: fsRemote /* smb2 read as a negative int32 */, 0x12345678: fsUnknown} {
		if _, got, _ := classifyMagic(magic); got != want {
			t.Errorf("%#x: %v, want %v", magic, got, want)
		}
	}
	var warned []string
	if _, err := checkPath(t.TempDir()+"/x.db", func(m string) { warned = append(warned, m) }); err != nil {
		t.Fatal(err)
	}
	for _, w := range warned {
		if !strings.Contains(w, "unrecognized filesystem") {
			t.Fatal(w)
		}
	}
}
