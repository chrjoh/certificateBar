package yaml

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

//var data = `
//ca: true
//pix:
//  commonname: www.foo.se
//  country: SE
//`

type PkixData struct {
	CommonName string `yaml:"commonname"`
	Country    string `yaml:"country"`
}
type Data struct {
	Id        string   `yaml:"id"`
	CA        bool     `yaml:"ca"`
	Parent    string   `yaml:"parent"`
	KeyType   string   `yaml:"keytype"`
	KeyLength int      `yaml:"keylength"`
	HashAlg   string   `yaml:"hashalg"`
	AltNames  []string `yaml:"altnames"`
	Pkix      PkixData `yaml:"pkix"`
}
type Cert struct {
	Certificate Data `yaml:"certificate"`
}
type Certs struct {
	Certificates []Cert `yaml:"certificates"`
}

func Handler() {
	test := Certs{}
	data := ReadFile("./config/data.yaml")
	err := yaml.Unmarshal(data, &test)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Printf("--- test:\n%v\n\n", test)
	fmt.Printf("country: %s\n", test.Certificates[2].Certificate.AltNames)
	test2 := Data{
		CA: false,
		Pkix: PkixData{
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

func ReadFile(name string) []byte {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		log.Println("Could not read file: %s\n", name)
		os.Exit(1)
	}
	return data
}
