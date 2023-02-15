package cmd

import (
	"testing"
)

func Test_encrypt(t *testing.T) {

	ca := ReadCA("./test.ca")

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
				ca:   ca,
				data: "this is secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encrypt(tt.args.ca, tt.args.data)

			if got = Decrypt(tt.args.ca, got); got != tt.args.data {
				t.Errorf("encrypt() = %v, want %v", got, tt.args.data)
			}
		})
	}
}
