package kes

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/msgp"
	bolt "go.etcd.io/bbolt"
)

// KES server states. See: TODO:link
const (
	Follower uint32 = iota
	Candidate
	Leader
)

// State represents the current state of a KES server.
type State struct {
	// Addr is the address of the server.
	//
	// Each server within a cluster must be able to communicate
	// to all other servers, its peers, via their addresses.
	Addr Addr

	// ID is the unique ID of the server within the cluster.
	//
	// A cluster may re-cycle server IDs when nodes leave the
	// cluster.
	ID int

	// Admin is the cluster admin identity.
	//
	// The cluster admin has root-level control over the cluster
	// and can perform arbitrary operations.
	//
	// If empty, cluster admin access is disabled.
	Admin kes.Identity

	// APIKey is the API key used for internode authentication.
	// For example, when the leader node replicates an event to
	// its followers.
	//
	// All servers within a cluster share the same API key.
	APIKey kes.APIKey

	// LeaderID is the ID of the current cluster leader, or
	// -1 if there is none.
	LeaderID int

	// State is the current state of the server, either: Follower,
	// Candidcate or Leader.
	State uint32

	// Commit is number of the most recent commit. It describes
	// how many write requests a cluster has processed.
	Commit uint64

	// Cluster
	Cluster map[int]Addr

	// HeartbeatInterval controls how often the leader sends
	// heartbeat events to its followers.
	HeartbeatInterval time.Duration

	// ElectionTimeout controls after which time follower nodes
	// become candidates if they haven't received heartbeat event.
	ElectionTimeout time.Duration
}

// IsLeader reports whether the server is the cluster leader.
func (s *State) IsLeader() bool { return s.State == Leader && s.ID == s.LeaderID }

// commit represents a KES commit persisted as part of
// command execution.
type commit struct {
	N       uint64 // The commit number
	Type    uint   // The command type
	Command []byte // The command binary encoded
}

func (c *commit) MarshalMsg() (msgp.Commit, error) {
	return msgp.Commit{
		N:     c.N,
		Type:  c.Type,
		Event: c.Command,
	}, nil
}

func (c *commit) UnmarshalMsg(v *msgp.Commit) error {
	c.N = v.N
	c.Type = v.Type
	c.Command = v.Event
	return nil
}

func initState(ctx context.Context, db *bolt.DB, hsm HSM) (crypto.SecretKey, commit, error) {
	var (
		c       commit
		rootKey crypto.SecretKey
	)
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(dbClusterBucket))
		if err != nil {
			return err
		}

		var encRootKey encryptedRootKey
		ciphertext := bytes.Clone(b.Get([]byte("root")))
		if ciphertext == nil {
			key, err := crypto.GenerateSecretKey(crypto.AES256, nil)
			if err != nil {
				return err
			}
			plaintext, err := msgp.Marshal(&key)
			if err != nil {
				return err
			}
			ciphertext, err = hsm.Seal(ctx, plaintext)
			if err != nil {
				return err
			}

			encRootKey.Set(hsm.Name(), ciphertext)
			ciphertext, err = msgp.Marshal(&encRootKey)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(dbClusterRootKey), bytes.Clone(ciphertext)); err != nil {
				return err
			}
		}

		if err = msgp.Unmarshal(ciphertext, &encRootKey); err != nil {
			return err
		}
		ciphertext, ok := encRootKey.Get(hsm.Name())
		if !ok {
			return errors.New("cluster: no encrypted root key for unseal provider '" + hsm.Name() + "' found")
		}
		plaintext, err := hsm.Unseal(ctx, ciphertext)
		if err != nil {
			return err
		}
		if err = msgp.Unmarshal(plaintext, &rootKey); err != nil {
			return err
		}

		s := bytes.Clone(b.Get([]byte(dbCommitKey)))
		if s == nil {
			return nil
		}
		s, err = rootKey.Decrypt(s, []byte(dbClusterBucket+"/"+dbCommitKey))
		if err != nil {
			return err
		}
		return msgp.Unmarshal(s, &c)
	}); err != nil {
		return crypto.SecretKey{}, commit{}, err
	}
	return rootKey, c, nil
}
