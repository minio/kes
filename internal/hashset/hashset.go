// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package hashset

func NewSet[T comparable](n int) Set[T] {
	return Set[T]{
		values: make(map[T]struct{}, n),
	}
}

func FromSlice[T comparable](values ...T) Set[T] {
	set := NewSet[T](len(values))
	for _, value := range values {
		set.Set(value)
	}
	return set
}

type Set[T comparable] struct {
	values map[T]struct{}
}

func (s Set[_]) Len() int { return len(s.values) }

func (s Set[T]) Contains(value T) bool {
	_, ok := s.values[value]
	return ok
}

func (s *Set[T]) Set(value T) {
	if s.values == nil {
		s.values = make(map[T]struct{})
	}
	s.values[value] = struct{}{}
}

func (s *Set[T]) Add(value T) bool {
	if _, ok := s.values[value]; ok {
		return false
	}

	s.Set(value)
	return true
}

func (s Set[T]) Delete(value T) {
	if s.values != nil {
		delete(s.values, value)
	}
}

func (s Set[T]) Clone() Set[T] {
	if s.values == nil {
		return Set[T]{}
	}
	clone := make(map[T]struct{}, len(s.values))
	for v := range s.values {
		clone[v] = struct{}{}
	}
	return Set[T]{values: clone}
}

func (s Set[T]) DeleteAll() {
	if s.values == nil {
		return
	}
	for v := range s.values {
		delete(s.values, v)
	}
}

func (s Set[T]) Values() map[T]struct{} {
	if s.values == nil {
		return map[T]struct{}{}
	}
	return s.values
}

func (s Set[T]) Slice() []T {
	if len(s.values) == 0 {
		return []T{}
	}

	values := make([]T, 0, len(s.values))
	for value := range s.values {
		values = append(values, value)
	}
	return values
}
