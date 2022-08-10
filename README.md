# pwned-client

[![Go Report Card](https://goreportcard.com/badge/github.com/masonschafercodes/pwned-client)](https://goreportcard.com/report/github.com/masonschafercodes/pwned-client)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://github.com/masonschafercodes/pwned-client/blob/master/LICENSE)

A [Go](http://golang.org) client to interact with the [HIBP API V2](https://haveibeenpwned.com/API/v2)

## Installation

`go get -u github.com/masonschafercodes/pwned-client`

## Usage

```go
package main

import (
    "fmt"
    "net/http"
    "os"
    "time"

    pwned "github.com/masonschafercodes/pwned-client"
)

func main() {
    // Init a client.
    client := pwned.NewPwnedClient()

    // Optional: Use a custom http client
    client.SetHTTPClient(&http.Client{
        Timeout: 10 * time.Second,
    })

    breachs, err := client.BreachByDomain("adobe.com")
    if err != nil {
        os.Exit(1)
    }

   for _, breach := range breachs {
    fmt.Println("Breach: " + breach)
   }
}
```

## Contributing

If you've found a bug or would like to contribute, please create an issue here on GitHub, or better yet fork the project and submit a pull request!
