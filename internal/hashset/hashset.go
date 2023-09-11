// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package hashset provides the generic container type Set.
package hashset

import "maps"

// New returns a new Set with an initial capacity of n.
//
// In certain cases, it may be more performant to
// create a Set with an initial capacity than creating
// an empty Set.
func New[T comparable](n int) Set[T] {
	return Set[T]{
		elems: make(map[T]struct{}, n),
	}
}

// FromSlice returns a new Set from a slice of
// elements. Duplicate elements in the slice
// are added to the Set only once.
func FromSlice[T comparable](elems ...T) Set[T] {
	set := New[T](len(elems))
	for _, value := range elems {
		set.Set(value)
	}
	return set
}

// A Set is a container type that contains a set
// of comparable elements. A Set can contain one
// specific element at most once.
type Set[T comparable] struct {
	elems map[T]struct{}
}

// Len returns the number of elements in the Set.
func (s Set[_]) Len() int { return len(s.elems) }

// Contains reports whether the Set contains the element.
func (s Set[T]) Contains(elem T) bool {
	_, ok := s.elems[elem]
	return ok
}

// Set inserts the element into the Set.
func (s *Set[T]) Set(elem T) {
	if s.elems == nil {
		s.elems = make(map[T]struct{})
	}
	s.elems[elem] = struct{}{}
}

// Add inserts the given element into the Set if, and
// only if, it isn't part of the Set already. It reports
// whether the element got added.
func (s *Set[T]) Add(elem T) bool {
	if _, ok := s.elems[elem]; ok {
		return false
	}

	s.Set(elem)
	return true
}

// Delete removes the element from the Set, if present.
func (s Set[T]) Delete(elem T) {
	if s.elems != nil {
		delete(s.elems, elem)
	}
}

// Clone returns a deep copy of the Set.
func (s Set[T]) Clone() Set[T] {
	if s.elems == nil {
		return Set[T]{}
	}

	return Set[T]{elems: maps.Clone(s.elems)}
}

// Clear removes all elements from the Set.
func (s Set[T]) Clear() {
	if len(s.elems) == 0 {
		return
	}

	for v := range s.elems {
		delete(s.elems, v)
	}
}

// Elements returns the underlying map containing
// the Set's elements. Adding or removing elements
// also modifies the Set.
func (s Set[T]) Elements() map[T]struct{} {
	if s.elems == nil {
		return map[T]struct{}{}
	}
	return s.elems
}

// Slice returns a slice of all elements within the Set.
func (s Set[T]) Slice() []T {
	if len(s.elems) == 0 {
		return []T{}
	}

	elems := make([]T, 0, len(s.elems))
	for elem := range s.elems {
		elems = append(elems, elem)
	}
	return elems
}
