// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/hashset"
	"github.com/minio/kes/internal/msgp"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
)

// KES command types.
const (
	cmdJoinCluster = iota
	cmdLeaveCluster

	cmdCreateEnclave
	cmdDeleteEnclave

	cmdCreateSecretKeyRing
	cmdDeleteSecretKeyRing

	cmdCreateSecret
	cmdDeleteSecret

	cmdCreateIdentity
	cmdDeleteIdentity

	cmdCreatePolicy
	cmdDeletePolicy
)

// compiler checks
var (
	_ command = (*joinClusterCmd)(nil)
	_ command = (*leaveClusterCmd)(nil)

	_ command = (*createEnclaveCmd)(nil)
	_ command = (*deleteEnclaveCmd)(nil)

	_ command = (*createSecretKeyRingCmd)(nil)
	_ command = (*deleteSecretKeyRingCmd)(nil)

	_ command = (*createSecretCmd)(nil)
	_ command = (*deleteSecretCmd)(nil)

	_ command = (*createIdentityCmd)(nil)
	_ command = (*deleteIdentityCmd)(nil)

	_ command = (*createPolicyCmd)(nil)
	_ command = (*deletePolicyCmd)(nil)
)

// A command represents a KES state change.
//
// Any command is applied by the current cluster
// leader first, and then replicated to its followers
// if and only if it executed without error.
//
// Since any command has to be executed by all nodes
// within a cluster, a command must be deterministic
// and self-contained.
// For example, an command must not use randomness
// to produce different / non-equivalent results.
// Otherwise, two nodes within a cluster may apply
// the same event but end up in different states.
type command interface {
	// Apply applies the command on the given
	// server using the given DB transaction.
	Apply(*Server, *bolt.Tx) error

	// Type returns a type identifier for the concrete
	// command.
	Type() uint
}

// encodeEvent encodes the given command or returns
// an error if the command is unknown or not supported.
func encodeEvent(cmd command) ([]byte, error) {
	switch cmd.Type() {
	default:
		return nil, fmt.Errorf("kes: command '%d' is unknown", cmd.Type())

	case cmdJoinCluster:
		return msgp.Marshal(cmd.(*joinClusterCmd))
	case cmdLeaveCluster:
		return msgp.Marshal(cmd.(*leaveClusterCmd))
	case cmdCreateEnclave:
		return msgp.Marshal(cmd.(*createEnclaveCmd))
	case cmdDeleteEnclave:
		return msgp.Marshal(cmd.(*deleteEnclaveCmd))
	case cmdCreateSecretKeyRing:
		return msgp.Marshal(cmd.(*createSecretKeyRingCmd))
	case cmdDeleteSecretKeyRing:
		return msgp.Marshal(cmd.(*deleteSecretKeyRingCmd))
	case cmdCreateSecret:
		return msgp.Marshal(cmd.(*createSecretCmd))
	case cmdDeleteSecret:
		return msgp.Marshal(cmd.(*deleteSecretCmd))
	case cmdCreateIdentity:
		return msgp.Marshal(cmd.(*createIdentityCmd))
	case cmdDeleteIdentity:
		return msgp.Marshal(cmd.(*deleteIdentityCmd))
	case cmdCreatePolicy:
		return msgp.Marshal(cmd.(*createPolicyCmd))
	case cmdDeletePolicy:
		return msgp.Marshal(cmd.(*deletePolicyCmd))
	}
}

// decodeEvent decodes and returns command from its binary
// representation.
func decodeEvent(cmdType uint, b []byte) (command, error) {
	switch cmdType {
	default:
		return nil, fmt.Errorf("kes: command '%d' is unknown", cmdType)

	case cmdJoinCluster:
		var cmd joinClusterCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdLeaveCluster:
		var cmd leaveClusterCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdCreateEnclave:
		var cmd createEnclaveCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdDeleteEnclave:
		var cmd deleteEnclaveCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdCreateSecretKeyRing:
		var cmd createSecretKeyRingCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdDeleteSecretKeyRing:
		var cmd deleteSecretKeyRingCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdCreateSecret:
		var cmd createSecretCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdDeleteSecret:
		var cmd deleteSecretCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdCreateIdentity:
		var cmd createIdentityCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdDeleteIdentity:
		var cmd deleteIdentityCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdCreatePolicy:
		var cmd createPolicyCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	case cmdDeletePolicy:
		var cmd deletePolicyCmd
		if err := msgp.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
		return &cmd, nil
	}
}

type joinClusterCmd struct {
	Cluster cluster
	Node    Addr
}

func (c *joinClusterCmd) Apply(s *Server, tx *bolt.Tx) error {
	cluster := maps.Clone(c.Cluster)
	if _, ok := cluster.Add(c.Node); !ok {
		return kes.NewError(http.StatusConflict, "server already part of the cluster")
	}

	if err := writeCluster(filepath.Join(s.path, fsClusterFile), cluster); err != nil {
		return err
	}

	s.id, _ = cluster.Lookup(s.addr)
	s.cluster = cluster
	notify(s.signals, SigJoin)
	return nil
}

func (*joinClusterCmd) Type() uint { return cmdJoinCluster }

func (c *joinClusterCmd) MarshalMsg() (msgp.JoinClusterCmd, error) {
	nodes := make(map[string]string, len(c.Cluster))
	for id, addr := range c.Cluster {
		nodes[strconv.Itoa(id)] = addr.String()
	}
	return msgp.JoinClusterCmd{
		Cluster: nodes,
		Node:    c.Node.String(),
	}, nil
}

func (c *joinClusterCmd) UnmarshalMsg(v *msgp.JoinClusterCmd) error {
	node, err := ParseAddr(v.Node)
	if err != nil {
		return err
	}

	cluster := make(map[int]Addr, len(v.Cluster))
	for k, addr := range v.Cluster {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}

		cluster[id], err = ParseAddr(addr)
		if err != nil {
			return err
		}
	}

	c.Cluster = cluster
	c.Node = node
	return nil
}

type leaveClusterCmd struct {
	Cluster cluster
	Node    Addr
}

func (c *leaveClusterCmd) Apply(s *Server, tx *bolt.Tx) error {
	cluster := maps.Clone(c.Cluster)
	id, ok := cluster.Remove(c.Node)
	if !ok {
		return kes.NewError(http.StatusConflict, "node not part of the cluster")
	}

	if err := writeCluster(filepath.Join(s.path, fsClusterFile), cluster); err != nil {
		return err
	}

	if s.id == id {
		s.shutdown.Store(true)
		return nil
	}

	s.cluster = cluster
	notify(s.signals, SigLeave)
	return nil
}

func (*leaveClusterCmd) Type() uint { return cmdLeaveCluster }

func (c *leaveClusterCmd) MarshalMsg() (msgp.LeaveClusterCmd, error) {
	nodes := make(map[string]string, len(c.Cluster))
	for id, addr := range c.Cluster {
		nodes[strconv.Itoa(id)] = addr.String()
	}
	return msgp.LeaveClusterCmd{
		Cluster: nodes,
		Node:    c.Node.String(),
	}, nil
}

func (c *leaveClusterCmd) UnmarshalMsg(v *msgp.LeaveClusterCmd) error {
	node, err := ParseAddr(v.Node)
	if err != nil {
		return err
	}

	cluster := make(map[int]Addr, len(v.Cluster))
	for k, addr := range v.Cluster {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}

		cluster[id], err = ParseAddr(addr)
		if err != nil {
			return err
		}
	}

	c.Cluster = cluster
	c.Node = node
	return nil
}

type createEnclaveCmd struct {
	Name      string
	Key       crypto.SecretKey
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (c *createEnclaveCmd) Apply(s *Server, tx *bolt.Tx) error {
	return createEnclave(tx, s.rootKey, c.Name, &Enclave{
		Key:       c.Key,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy,
	})
}

func (*createEnclaveCmd) Type() uint { return cmdCreateEnclave }

func (c *createEnclaveCmd) MarshalMsg() (msgp.CreateEnclaveCmd, error) {
	key, err := c.Key.MarshalMsg()
	if err != nil {
		return msgp.CreateEnclaveCmd{}, err
	}
	return msgp.CreateEnclaveCmd{
		Name:      c.Name,
		Key:       key,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy.String(),
	}, nil
}

func (c *createEnclaveCmd) UnmarshalMsg(v *msgp.CreateEnclaveCmd) error {
	var key crypto.SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	c.Name = v.Name
	c.Key = key
	c.CreatedAt = v.CreatedAt
	c.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

type deleteEnclaveCmd struct {
	Name string
}

func (c *deleteEnclaveCmd) Apply(_ *Server, tx *bolt.Tx) error {
	return deleteEnclave(tx, c.Name)
}

func (*deleteEnclaveCmd) Type() uint { return cmdDeleteEnclave }

func (c *deleteEnclaveCmd) MarshalMsg() (msgp.DeleteEnclaveCmd, error) {
	return msgp.DeleteEnclaveCmd{
		Name: c.Name,
	}, nil
}

func (c *deleteEnclaveCmd) UnmarshalMsg(v *msgp.DeleteEnclaveCmd) error {
	c.Name = v.Name
	return nil
}

type createSecretKeyRingCmd struct {
	Enclave   string
	Name      string
	Key       crypto.SecretKey
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (c *createSecretKeyRingCmd) Apply(s *Server, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, s.rootKey, c.Enclave)
	if err != nil {
		return err
	}
	var ring crypto.SecretKeyRing
	if err = ring.Add(crypto.SecretKeyVersion{
		Key:       c.Key,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy,
	}); err != nil {
		return err
	}
	return createSecretKeyRing(tx, enc.Key, c.Enclave, c.Name, &ring)
}

func (*createSecretKeyRingCmd) Type() uint { return cmdCreateSecretKeyRing }

func (c *createSecretKeyRingCmd) MarshalMsg() (msgp.CreateSecretKeyRingCmd, error) {
	key, err := c.Key.MarshalMsg()
	if err != nil {
		return msgp.CreateSecretKeyRingCmd{}, err
	}
	return msgp.CreateSecretKeyRingCmd{
		Enclave:   c.Enclave,
		Name:      c.Name,
		Key:       key,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy.String(),
	}, nil
}

func (c *createSecretKeyRingCmd) UnmarshalMsg(v *msgp.CreateSecretKeyRingCmd) error {
	var key crypto.SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	c.Enclave = v.Enclave
	c.Name = v.Name
	c.Key = key
	c.CreatedAt = v.CreatedAt
	c.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

type deleteSecretKeyRingCmd struct {
	Enclave string
	Name    string
}

func (c *deleteSecretKeyRingCmd) Apply(_ *Server, tx *bolt.Tx) error {
	return deleteSecretKeyRing(tx, c.Enclave, c.Name)
}

func (*deleteSecretKeyRingCmd) Type() uint { return cmdDeleteSecretKeyRing }

func (c *deleteSecretKeyRingCmd) MarshalMsg() (msgp.DeleteSecretKeyRingCmd, error) {
	return msgp.DeleteSecretKeyRingCmd{
		Enclave: c.Enclave,
		Name:    c.Name,
	}, nil
}

func (c *deleteSecretKeyRingCmd) UnmarshalMsg(v *msgp.DeleteSecretKeyRingCmd) error {
	c.Enclave = v.Enclave
	c.Name = v.Name
	return nil
}

type createSecretCmd struct {
	Enclave    string
	Name       string
	Secret     []byte
	SecretType crypto.SecretType
	CreatedAt  time.Time
	CreatedBy  kes.Identity
}

func (c *createSecretCmd) Apply(s *Server, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, s.rootKey, c.Enclave)
	if err != nil {
		return err
	}
	var secret crypto.Secret
	if err = secret.Add(crypto.SecretVersion{
		Value:     c.Secret,
		Type:      c.SecretType,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy,
	}); err != nil {
		return err
	}
	return createSecret(tx, enc.Key, c.Enclave, c.Name, &secret)
}

func (*createSecretCmd) Type() uint { return cmdCreateSecret }

func (c *createSecretCmd) MarshalMsg() (msgp.CreateSecretCmd, error) {
	return msgp.CreateSecretCmd{
		Enclave:    c.Enclave,
		Name:       c.Name,
		Secret:     c.Secret,
		SecretType: uint(c.SecretType),
		CreatedAt:  c.CreatedAt,
		CreatedBy:  c.CreatedBy.String(),
	}, nil
}

func (c *createSecretCmd) UnmarshalMsg(v *msgp.CreateSecretCmd) error {
	c.Enclave = v.Enclave
	c.Name = v.Name
	c.Secret = v.Secret
	c.SecretType = crypto.SecretType(v.SecretType)
	c.CreatedAt = v.CreatedAt
	c.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

type deleteSecretCmd struct {
	Enclave string
	Name    string
}

func (c *deleteSecretCmd) Apply(_ *Server, tx *bolt.Tx) error {
	return deleteSecret(tx, c.Enclave, c.Name)
}

func (*deleteSecretCmd) Type() uint { return cmdDeleteSecret }

func (c *deleteSecretCmd) MarshalMsg() (msgp.DeleteSecretCmd, error) {
	return msgp.DeleteSecretCmd{
		Enclave: c.Enclave,
		Name:    c.Name,
	}, nil
}

func (c *deleteSecretCmd) UnmarshalMsg(v *msgp.DeleteSecretCmd) error {
	c.Enclave = v.Enclave
	c.Name = v.Name
	return nil
}

type createIdentityCmd struct {
	Enclave   string
	Identity  kes.Identity
	IsAdmin   bool
	Policy    string
	TTL       time.Duration
	ExpiresAt time.Time
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (c *createIdentityCmd) Apply(s *Server, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, s.rootKey, c.Enclave)
	if err != nil {
		return err
	}
	return createIdentity(tx, enc.Key, c.Enclave, c.Identity, &auth.Identity{
		Identity:  c.Identity,
		Policy:    c.Policy,
		IsAdmin:   c.IsAdmin,
		Children:  hashset.Set[kes.Identity]{},
		TTL:       c.TTL,
		ExpiresAt: c.ExpiresAt,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy,
	})
}

func (*createIdentityCmd) Type() uint { return cmdCreateIdentity }

func (c *createIdentityCmd) MarshalMsg() (msgp.CreateIdentityCmd, error) {
	return msgp.CreateIdentityCmd{
		Enclave:   c.Enclave,
		Identity:  c.Identity.String(),
		Policy:    c.Policy,
		IsAdmin:   c.IsAdmin,
		TTL:       c.TTL,
		ExpiresAt: c.ExpiresAt,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy.String(),
	}, nil
}

func (c *createIdentityCmd) UnmarshalMsg(v *msgp.CreateIdentityCmd) error {
	c.Enclave = v.Enclave
	c.Identity = kes.Identity(v.Identity)
	c.Policy = v.Policy
	c.IsAdmin = v.IsAdmin
	c.TTL = v.TTL
	c.ExpiresAt = v.ExpiresAt
	c.CreatedAt = v.CreatedAt
	c.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

type deleteIdentityCmd struct {
	Enclave  string
	Identity kes.Identity
}

func (c *deleteIdentityCmd) Apply(s *Server, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, s.rootKey, c.Enclave)
	if err != nil {
		return err
	}

	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(c.Enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbIdentityBucket)); b == nil {
		return nil
	}
	return deleteIdentity(b, enc.Key, c.Enclave, c.Identity)
}

func (*deleteIdentityCmd) Type() uint { return cmdDeleteIdentity }

func (c *deleteIdentityCmd) MarshalMsg() (msgp.DeleteIdentityCmd, error) {
	return msgp.DeleteIdentityCmd{
		Enclave:  c.Enclave,
		Identity: string(c.Identity),
	}, nil
}

func (c *deleteIdentityCmd) UnmarshalMsg(v *msgp.DeleteIdentityCmd) error {
	c.Enclave = v.Enclave
	c.Identity = kes.Identity(v.Identity)
	return nil
}

type createPolicyCmd struct {
	Enclave   string
	Name      string
	Allow     map[string]auth.Rule
	Deny      map[string]auth.Rule
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (c *createPolicyCmd) Apply(s *Server, tx *bolt.Tx) error {
	enc, err := readEnclave(tx, s.rootKey, c.Enclave)
	if err != nil {
		return err
	}
	return createPolicy(tx, enc.Key, c.Enclave, c.Name, &auth.Policy{
		Allow:     c.Allow,
		Deny:      c.Deny,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy,
	})
}

func (*createPolicyCmd) Type() uint { return cmdCreatePolicy }

func (c *createPolicyCmd) MarshalMsg() (msgp.CreatePolicyCmd, error) {
	return msgp.CreatePolicyCmd{
		Enclave:   c.Enclave,
		Name:      c.Name,
		Allow:     c.Allow,
		Deny:      c.Deny,
		CreatedAt: c.CreatedAt,
		CreatedBy: c.CreatedBy.String(),
	}, nil
}

func (c *createPolicyCmd) UnmarshalMsg(v *msgp.CreatePolicyCmd) error {
	c.Enclave = v.Enclave
	c.Name = v.Name
	c.Allow = v.Allow
	c.Deny = v.Deny
	c.CreatedAt = v.CreatedAt
	c.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

type deletePolicyCmd struct {
	Enclave string
	Name    string
}

func (c *deletePolicyCmd) Apply(_ *Server, tx *bolt.Tx) error {
	return deletePolicy(tx, c.Enclave, c.Name)
}

func (*deletePolicyCmd) Type() uint { return cmdDeletePolicy }

func (c *deletePolicyCmd) MarshalMsg() (msgp.DeletePolicyCmd, error) {
	return msgp.DeletePolicyCmd{
		Enclave: c.Enclave,
		Name:    c.Name,
	}, nil
}

func (c *deletePolicyCmd) UnmarshalMsg(v *msgp.DeletePolicyCmd) error {
	c.Enclave = v.Enclave
	c.Name = v.Name
	return nil
}
