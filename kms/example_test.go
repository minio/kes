package kms_test

import (
	"fmt"
	"log"
)

func ExampleIter() {
	names := []string{
		"key-1",
		"key-2",
		"key-3",
	}
	iter := &Iter{
		Values: names,
	}
	defer iter.Close() // Make sure we close the iterator

	// Loop over the Iter until Next returns false.
	// Then we either reached EOF or encountered an
	// error.
	for iter.Next() {
		fmt.Println(iter.Name())
	}

	// Check whether we encountered an error while
	// iterating or encounter an error when closing
	// the iterator.
	if err := iter.Close(); err != nil {
		log.Fatalln(err)
	}
	// Output: key-1
	// key-2
	// key-3
}

type Iter struct {
	Values []string
	name   string
	closed bool
}

func (i *Iter) Next() bool {
	if i.closed || len(i.Values) == 0 {
		return false
	}
	i.name = i.Values[0]
	i.Values = i.Values[1:]
	return true
}

func (i *Iter) Name() string { return i.name }

func (i *Iter) Close() error {
	i.closed, i.name = true, ""
	return nil
}
