package cmd

import (
	"testing"
)

func Test_encrypt(t *testing.T) {

	user := ReadCA("./user.ca")
	root := ReadCA("./root.ca")
	token := "0I9RrrBcOIYhYwBvOznS76uITeixrzYujX2ynEsR1CtCaaknGCqGEELstuTyqMs4B3nqlTeVxonyRHglmQ8QhUkFxvnIMnAbyigFVLEPJfV4VCwXg+M5S6tzmlzt8VP6TdFtKujN2gKVuA5nKXLlxkgg6IxNfZt63/Fz/fMcDjo="
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
