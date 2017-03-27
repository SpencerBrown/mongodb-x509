package main

import (
	"fmt"
	"github.com/pelletier/go-toml"
)

func main() {

	config, err := toml.LoadFile("test.toml")
	if err != nil {
		fmt.Println("Error ", err.Error())
		return
	}

	somekey := config.Get("somekey").(string)
	someotherkey := config.Get("someotherkey").(int64)
	fmt.Println(somekey, "  ", someotherkey)



}
