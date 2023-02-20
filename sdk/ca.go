package sdk

import (
	"os"
)

func ReadCA(path string) string {
	ca, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(ca)
}
