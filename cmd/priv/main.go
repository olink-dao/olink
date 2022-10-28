package main

import (
	"fmt"
	"os"
	"github.com/olink/go-olink/alecthomas/kingpin.v2"

	"github.com/olink/go-olink/common"
	"github.com/olink/go-olink/accounts/keystore"
	"github.com/olink/go-olink/common/hexutil"
	"strings"

)

var (
	app = kingpin.New("priv", "tool for transfer keystore to priv")

	transfer = app.Command("transfer", "get privkey for given address")
	addr = transfer.Flag("addr", "given an address").Required().String()
	dir = transfer.Flag("keydir", "given the keystore dir").Required().String()
	pass = transfer.Flag("password", "given the unlock password").Required().String()
)


func main() {
	kingpin.Version("1.0.0")
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	case transfer.FullCommand():
		address := common.HexToAddress(*addr)
		ks := keystore.NewKeyStore(*dir, keystore.LightScryptN, keystore.LightScryptP)
		accs := ks.Accounts()
		for _, acc := range accs {
			if acc.Address == address {
				_, key, err := ks.GetDecryptedKey(acc, *pass)
				if err != nil {
					fmt.Printf("err:%v\r\n", err)
					return
				} else {
					privKey := (*hexutil.Big)(key.PrivateKey.D)
					fmt.Printf("privkey:%v\r\n", strings.Replace(privKey.String(), "0x", "", -1))
					return
				}
			}
		}

		fmt.Printf("not found the given address: \r\n")
	}
}