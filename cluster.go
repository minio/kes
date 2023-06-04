// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	fsDBFile      = "kes.db"
	fsClusterFile = ".cluster.json"
)

// Init initializes the given directory by creating
// the DB and single-node cluster definition from
// the given Addr. It creates dir if no such directory
// exists.
//
// If dir is already initialized, Init does nothing.
func Init(dir string, addr Addr) error {
	err := os.Mkdir(dir, 0o755)         // More efficient than MkdirAll right away
	if errors.Is(err, os.ErrNotExist) { // If any parent dir does not exist, Mkdir returns ErrNotExist
		err = os.MkdirAll(dir, 0o755)
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}

	clusterFile := filepath.Join(dir, fsClusterFile)
	if _, err = os.Stat(clusterFile); errors.Is(err, os.ErrNotExist) {
		if err = writeCluster(clusterFile, map[int]Addr{0: addr}); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	dbFile := filepath.Join(dir, fsDBFile)
	if _, err = os.Stat(dbFile); errors.Is(err, os.ErrNotExist) {
		var db *bolt.DB
		db, err = bolt.Open(dbFile, 0o640, &bolt.Options{
			Timeout:      3 * time.Second,
			FreelistType: bolt.FreelistMapType,
		})
		if err != nil {
			return err
		}
		if err = db.Close(); err != nil {
			return err
		}
	}
	return err
}

// initCluster reads a cluster from the given file and returns
// the ID of the given Addr within the cluster. It returns an
// error if the Addr is not part of the cluster.
//
// If no such file exists, initCluster assigns the given Addr
// the ID '0' and creates a new cluster file.
func initCluster(filename string, addr Addr) (cluster, int, error) {
	cluster, err := readCluster(filename)
	if errors.Is(err, os.ErrNotExist) {
		err = writeCluster(filename, map[int]Addr{0: addr})
		if err != nil {
			return nil, 0, err
		}
		cluster, err = readCluster(filename)
	}
	if err != nil {
		return nil, 0, err
	}

	self, ok := cluster.Lookup(addr)
	if !ok {
		return nil, 0, fmt.Errorf("kes: addr '%s' is not part of the cluster", addr)
	}
	return cluster, self, nil
}

// readCluster parses and returns a cluster from the given file.
// It returns an error if the cluster contains the same Addr more
// than once.
func readCluster(filename string) (cluster, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	m := make(map[string]string)
	if err = json.NewDecoder(file).Decode(&m); err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil { // Close FD early
		return nil, err
	}

	cluster := make(map[int]Addr, len(m))
	addrs := make(map[Addr]struct{}, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		if id < 0 {
			return nil, errors.New("kes: invalid cluster state: ID must not be negative")
		}

		addr, err := ParseAddr(v)
		if err != nil {
			return nil, err
		}
		if _, ok := addrs[addr]; ok {
			return nil, fmt.Errorf("kes: invalid cluster state: multiple IDs refer to the same address '%s'", addr)
		}

		cluster[id] = addr
		addrs[addr] = struct{}{}
	}

	return cluster, nil
}

// writeCluster encodes and writes the cluster to the given file.
// It returns an error if the cluster contains the same Addr more
// than once.
func writeCluster(filename string, c cluster) error {
	m := make(map[string]string, len(c))
	addrs := make(map[Addr]struct{}, len(c))
	for id, addr := range c {
		if _, ok := addrs[addr]; ok {
			return fmt.Errorf("kes: invalid cluster state: multiple IDs refer to the same address '%s'", addr)
		}

		m[strconv.Itoa(id)] = addr.String()
		addrs[addr] = struct{}{}
	}

	// We first write to a tmp file and use os.Rename to ensure that we
	// either write a valid cluster file in case of success or preserve
	// a previous cluster file, if any, in case of an error.
	tmp := filename + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_EXCL|os.O_SYNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // Make sure the tmp file gets removed since os.O_CREATE|os.O_EXCL
	defer file.Close()   // Close the file before removing it

	if err = json.NewEncoder(file).Encode(m); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filename)
}

// cluster defines a KES cluster as mapping from Node ID
// to Node Addr.
//
// A cluster must not contain the same Addr twice. For
// adding or removing an Addr use the corresponding
// methods.
//
// Node IDs must not be negative.
type cluster map[int]Addr

// Lookup returns the ID for the given Addr and
// a bool indicating whether the Addr is part of
// the cluster.
func (c cluster) Lookup(addr Addr) (int, bool) {
	for i, a := range c {
		if addr.Equal(a) {
			return i, true
		}
	}
	return -1, false
}

// Add adds the Addr to the cluster if and only if
// it isn't part of the cluster already. It returns
// the ID of the Addr and a bool indicating whether
// the Addr has been added.
//
// Add re-assigns IDs of removed Addrs. Hence, when
// an Addr is added again it obtains the next
// available, and not its previous, ID.
func (c cluster) Add(addr Addr) (int, bool) {
	for id, a := range c {
		if addr.Equal(a) {
			return id, false
		}
	}

	for i := 0; i < len(c); i++ {
		if _, ok := c[i]; !ok {
			c[i] = addr
			return i, true
		}
	}

	id := len(c)
	c[id] = addr
	return id, true
}

// Remove removes the Addr from the cluster. It
// returns the Addr's ID and a bool indicating
// whether the Addr was part of the cluster.
//
// When an Addr is added again it obtains the
// next available, and not its previous, ID.
func (c cluster) Remove(addr Addr) (int, bool) {
	for id, a := range c {
		if addr.Equal(a) {
			delete(c, id)
			return id, true
		}
	}
	return -1, false
}
