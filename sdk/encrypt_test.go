package sdk

import (
	"testing"
)

func Test_encrypt(t *testing.T) {
	// 3465489781857462659
	url := "http://192.168.200.58:8096/api/ca/gendynamtoken?orgId=&userId=&userType=&certUsage=&certSn=&token=" // prod
	certID := "4340649902272900003"

	s := &Security{
		Url:      url,
		CertID:   certID,
		RootPath: "./root.ca",
		UserPath: "./user.ca",
	}

	type args struct {
		s    *Security
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
				s:    s,
				data: "this is secret",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := s.EncryptData(tt.args.data)
			gots := make([]string, 0)
			gots = append(gots, got)
			if r, _ := s.DecrypDatas(gots); r[0] != tt.args.data {
				t.Errorf("encrypt() = %v, want %v", r, tt.args.data)
			}
		})
	}
}
