package cmd

import (
	"testing"
)

func Test_encrypt(t *testing.T) {

	user := ReadCA("./user.ca")
	root := ReadCA("./root.ca")
	token := "+OChKJsaP1uQZwNjwe8LI/5lpRHQNgVb8NKiwYKcvjUjtTcN3HVW3y+wyOHxdPg6TgnWUtIpI6Hd2JZI2XMdJSxHC7GxHIUsk5BlO9foZyJIfhIsYDv0RpAS+qvHM+n6/H82skUgKs8jy3jhGLtl90CMtn3vF9TTBSYcWxTte4E="
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
