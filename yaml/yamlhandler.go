package yaml

import (
	"fmt"
	"log"

	"gopkg.in/yaml.v2"
)

var data = `
ca: yes
pix:
  commonname: www.foo.se
  country: SE
`

type PixData struct {
	CommonName string `yaml:"commonname"`
	Country    string `yaml:"country"`
}
type Data struct {
	CA  string  `yaml:"ca"`
	Pix PixData `yaml:"pix"`
}

func Handler() {
	test := Data{}
	err := yaml.Unmarshal([]byte(data), &test)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Printf("--- test:\n%v\n\n", test)
	fmt.Printf("country: %s\n", test.Pix.Country)
	test2 := Data{
		CA: "yes",
		Pix: PixData{
			CommonName: "www.foo.se",
			Country:    "SE",
		},
	}
	d, err := yaml.Marshal(&test2)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Printf("--- test2 dump:\n%s\n\n", string(d))

}
