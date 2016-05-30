package himitsu

import (
	"reflect"
)

func Zero(in []byte, cycles int) {
	for i := 0; i < cycles; i++ {
		for i := 0; i < len(in); i++ {
			in[i] = 0x00
		}
		for i := 0; i < len(in); i++ {
			in[i] = 0xFF
		}
	}
}

func Clear(v interface{}) {
	p := reflect.ValueOf(v).Elem()
	p.Set(reflect.Zero(p.Type()))
}
