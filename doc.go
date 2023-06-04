// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// The kes package provides a KES server implementation.
//
// ## Servers
//
// A KES server is a stateful HTTP server that maintains
// its state on disk and uses a local key-value database for
// transactions. The database is encrypted and can only be
// unsealed by a (hardware) security module. Refer to the
// HSM interface type. The KES package also provides a simple
// software emulation of an HSM via the SoftHSM type.
//
// ## Clusters
//
// A KES cluster consists of an arbitrary number of servers.
// A single server represents the smallest cluster with just
// a single node. A cluster expands or shrinks dynamically
// when servers join or leave the cluster.
//
// All server nodes within a cluster participate in a consensus
// algorithm inspired by Raft: https://raft.github.io/raft.pdf
//
// ## Consensus
//
// The KES cluster is similar to the Raft consensus algorithm.
// In particular, a KES cluster performs leader election. At any
// point in time, there is at most one leader within a cluster.
// This cluster leader is responsible for all write requests (cluster
// state modifications) and replicates its changes to its follower
// nodes. In case of a leader failure, the remaining follower nodes
// start a leader election process. At most one server node can win
// the election and establish itself as the new leader. For a more
// elaborate explanation, refer to the Raft paper.
//
// However, the KES cluster consensus also differs from Raft in various
// aspects and makes certain trade-offs with respect to availability
// and consistency:
//
//  1. A KES cluster can only make progress (process write requests) as long
//     as there is a leader and all N nodes are available. In Raft, a cluster
//     can make progress as long as there is a leader and a majority (N/2 + 1)
//     of the nodes are available.
//  2. A KES cluster provides strict consistency as long as at least one node
//     is available. In Raft, a cluster can only guarantee strict consistency
//     as long as there is a leader and a majority (N/2 + 1) of the nodes are
//     available. Furthermore, a Raft cluster has to make additional performance
//     trade-offs to ensure strict consistency even if a majority is available.
//
// In summary, a KES cluster tolerates fewer node failures than a Raft cluster
// with respect to write availability. However, it tolerates more node failures
// with respect to read availability. Furthermore, a KES cluster guarantees
// strict consistency without any throughput or performance costs, while Raft
// clusters have to perform additional operations to prevent stale reads.
package kes
