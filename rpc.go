// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
)

func replicate(ctx context.Context, client *http.Client, addr Addr, req api.ReplicateRPCRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, addr.URL(api.PathClusterRPCReplicate).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

func forward(ctx context.Context, client *http.Client, addr Addr, req api.ForwardRPCRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, addr.URL(api.PathClusterRPCForward).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

func requestVote(ctx context.Context, client *http.Client, addr Addr, req api.VoteRPCRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, addr.URL(api.PathClusterRPCVote).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

func expandCluster(ctx context.Context, client *http.Client, addr Addr, body *io.PipeReader, size int64) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, addr.URL(api.PathClusterRestore).String(), body)
	if err != nil {
		return err
	}
	r.ContentLength = size

	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return kes.NewError(resp.StatusCode, resp.Status)
	}
	return nil
}
