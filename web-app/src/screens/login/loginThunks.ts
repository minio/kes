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

import { createAsyncThunk } from "@reduxjs/toolkit";
import { RootState } from "../../app/store";
import api from "../../common/api";
import { ErrorResponseHandler } from "../../common/api/types";
import { setErrorSnackMessage, userLogged } from "../../systemSlice";
import { setNavigateTo } from "./loginSlice";

export const getTargetPath = () => {
  let targetPath = "/encryption/keys";
  if (
    localStorage.getItem("redirect-path") &&
    localStorage.getItem("redirect-path") !== ""
  ) {
    targetPath = `${localStorage.getItem("redirect-path")}`;
    localStorage.setItem("redirect-path", "");
  }
  return targetPath;
};

export const doLoginAsync = createAsyncThunk(
  "login/doLoginAsync",
  async (_, { getState, rejectWithValue, dispatch }) => {
    const state = getState() as RootState;
    const apiKey = state.login.apiKey;
    const insecure = state.login.insecure;
    const password = state.login.password;
    const fileCertToUpload = state.login.fileCertToUpload;
    const fileKeyToUpload = state.login.fileKeyToUpload;

    const formData = new FormData();
    if (fileCertToUpload) {
      formData.append("cert", fileCertToUpload, "client.cert");
    }
    if (fileKeyToUpload) {
      formData.append("key", fileKeyToUpload, "client.key");
    }
    formData.append("apiKey", apiKey);
    formData.append("password", password);
    formData.append("insecure", insecure.toString());

    return api
      .invoke("POST", "/api/v1/login", formData)
      .then((res) => {
        // We set the state in redux
        dispatch(userLogged(true));
        localStorage.setItem("userLoggedIn", "");
        dispatch(setNavigateTo(getTargetPath()));
      })
      .catch((err) => {
        dispatch(setErrorSnackMessage(err));
      });
  }
);
export const getFetchConfigurationAsync = createAsyncThunk(
  "login/getFetchConfigurationAsync",
  async (_, { getState, rejectWithValue, dispatch }) => {
    return api
      .invoke("GET", "/api/v1/login")
      .then((loginDetails) => {
        return loginDetails;
      })
      .catch((err: ErrorResponseHandler) => {
        dispatch(setErrorSnackMessage(err));
      });
  }
);
