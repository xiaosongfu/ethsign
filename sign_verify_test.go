package ethsign

import "testing"

func TestSignVerify(t *testing.T) {
	tests := []struct {
		name    string
		message string
		sign    string
		pubAddr string
		want    bool
	}{
		{
			name:    "success-test",
			message: "hello eth",
			sign:    "0xbdf573b80076af5e2516bcf1d6957656efbaec16268af79b0f678e86dc8a2aca08b280c0ace5967d48586a72788c88a80f61657426c49fa065848f55d4fb9aed1b",
			pubAddr: "0xc1eE7cB74583D1509362467443C44f1FCa981283",
			want:    true,
		},
	}

	for _, tt := range tests {
		got, err := SignVerify(tt.message, tt.sign, tt.pubAddr)
		if err != nil {
			t.Error(err)
		}

		if got != tt.want {
			t.Errorf("[%s] test failed, want [%v], got [%v]", tt.name, tt.want, got)
		}
	}
}
