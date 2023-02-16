package cmd

import (
	"testing"
)

func Test_encrypt(t *testing.T) {

	user := ReadCA("./user.ca")
	root := ReadCA("./root.ca")
	token := "qg203u4GCP+vPD4kZMt/xjuAptvh0dXuGftFhwAUREHmNbQYSHv8T143hoXw31tOV6+30atTp5j0LTX/NFQSEVF3IlPUUqtJYu0dZwHcdY7W6zDY72kNgDm1UF2D4A0cSUbEN+lq/fkbTLTeuLOTNuQwoha7FH5zhK7wipzMgko="
	type args struct {
		ca   string
		data string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			args: args{
				ca:   user,
				data: "this is secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncryptData(tt.args.ca, tt.args.data)

			if got = DecrypData(root, token, got); got != tt.args.data {
				t.Errorf("encrypt() = %v, want %v", got, tt.args.data)
			}
		})
	}
}
