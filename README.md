# Example usage
`go get -u github.com/rislah/rsocks`

```
package main

import (
	"fmt"
	"github.com/rislah/rsocks"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)


func main() {
	socks, err := rsocks.New("80.211.165.175:48484", 10*time.Second, rsocks.Socks5)
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		DialContext: socks.Dialer(),
	}

	client := &http.Client{
		Transport: tr,
	}

	res, err := client.Get("https://httpbin.org/get?show_env")
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(body))
}
````
