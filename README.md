# goksef

`goksef` is a Go client library for interacting with the KSeF (Krajowy System e-Faktur) API. This package provides an easy-to-use interface for integrating with the Polish e-Invoicing system.

## Features

- Simplified interaction with the KSeF API.
- Support for authentication and request signing.
- Easy integration into Go projects.

## Installation

```bash
go get github.com/onit-soft/goksef
```

## Usage

```go
package main

import (
    "github.com/onit-soft/goksef/goksef"
)

func main() {
    client := goksef.NewClient("https://ksef-test.mf.gov.pl")
    // Use the client to interact with the KSeF API
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
