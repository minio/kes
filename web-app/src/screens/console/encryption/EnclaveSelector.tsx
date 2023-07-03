// This file is part of MinIO KES
// Copyright (c) 2023 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import React, { useEffect, useState } from "react";

import { useAppDispatch, useAppSelector } from "../../../app/hooks";
import { setErrorSnackMessage } from "../../../systemSlice";
import { Select } from "mds";
import api from "../../../common/api";
import { setEnclave } from "./encryptionSlice";

const EnclaveSelector = () => {
  const dispatch = useAppDispatch();
  const enclave = useAppSelector((state) => state.encryption.enclave);
  console.log("enclave", enclave);
  const [loading, setLoading] = useState<boolean>(false);
  const [enclaveList, setEnclaveList] = useState<string[]>([enclave]);
  useEffect(() => {
    setLoading(true);
  }, []);

  const getEnclaveList = () => {
    api
      .invoke("GET", "/api/v1/encryption/enclaves")
      .then((res) => {
        setLoading(false);
        setEnclaveList(res.data);
      })
      .catch((err) => {
        setLoading(false);
        setEnclaveList(["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
        dispatch(setErrorSnackMessage(err));
      });
  };

  useEffect(() => {
    getEnclaveList();
  }, [loading]);

  return (
    <Select
      id="enclave-select"
      onChange={(v) => {
        dispatch(setEnclave(v));
      }}
      options={enclaveList.map((e) => {
        return { label: e, value: e };
      })}
      value={enclave}
    />
  );
};

export default EnclaveSelector;
