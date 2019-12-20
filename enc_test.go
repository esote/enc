package enc

import (
	"testing"
)

func TestIdempotent(t *testing.T) {
	type Line struct {
		C, M string
	}

	before := Line{
		C: "PICARD",
		M: `"'A matter of internal security.' The age-old cry of the oppressor."`,
	}

	const pass = "trek"

	data, _, err := Encrypt([]byte(pass), &before)

	if err != nil {
		t.Fatal(err)
	}

	var after Line
	if err = Decrypt(data, []byte(pass), &after); err != nil {
		t.Fatal(err)
	}

	if after != before {
		t.Fatal("after != before")
	}
}
