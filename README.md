# Simple MySQL AES_ENCRYPT() and AES_DECRYPT() in golang

## Installation

```shell
go get -u github.com/allape/gomysqlaes
```

## Example

```go
package main

import (
	"fmt"
	"github.com/allape/gomysqlaes"
)

const MyLittleTinyTeenySecret = "plain"
const Password = "12345678"

func main() {
	hex, err := gomysqlaes.EncryptToHex(MyLittleTinyTeenySecret, Password)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex)

	plain, err := gomysqlaes.DecryptFromHex(hex, Password)
	if err != nil {
		panic(err)
	}
	fmt.Println(plain)
}

```
