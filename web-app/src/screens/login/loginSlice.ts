// This file is part of MinIO Console Server
// Copyright (c) 2022 MinIO, Inc.
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

import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { RootState } from "../../app/store";
import { doLoginAsync } from "./loginThunks";
import { ILoginDetails, loginStrategyType } from "./types";

export interface LoginState {
  apiKey: string;
  password: string;
  accessKey: string;
  secretKey: string;
  insecure: boolean;
  loginStrategy: ILoginDetails;
  loginSending: boolean;
  navigateTo: string;
  fileCertToUpload: Blob | null;
  fileKeyToUpload: Blob | null;
}

const initialState: LoginState = {
  apiKey: "",
  password: "",
  accessKey: "",
  secretKey: "",
  insecure: false,
  loginStrategy: {
    loginStrategy: loginStrategyType.unknown,
    redirectRules: [],
  },
  loginSending: false,

  navigateTo: "",
  fileCertToUpload: null,
  fileKeyToUpload: null,
};

export const loginSlice = createSlice({
  name: "login",
  initialState,
  reducers: {
    setApiKey: (state, action: PayloadAction<string>) => {
      state.apiKey = action.payload;
    },
    setPassword: (state, action: PayloadAction<string>) => {
      state.password = action.payload;
    },
    setAccessKey: (state, action: PayloadAction<string>) => {
      state.accessKey = action.payload;
    },
    setSecretKey: (state, action: PayloadAction<string>) => {
      state.secretKey = action.payload;
    },
    setNavigateTo: (state, action: PayloadAction<string>) => {
      state.navigateTo = action.payload;
    },
    setInsecure: (state, action: PayloadAction<boolean>) => {
      state.insecure = action.payload;
    },
    setFileCertToUpload: (state, action: PayloadAction<Blob | null>) => {
      state.fileCertToUpload = action.payload;
    },
    setFileKeyToUpload: (state, action: PayloadAction<Blob | null>) => {
      state.fileKeyToUpload = action.payload;
    },
    resetForm: (state) => initialState,
  },
  extraReducers: (builder) => {
    builder
      .addCase(doLoginAsync.pending, (state, action) => {
        state.loginSending = true;
      })
      .addCase(doLoginAsync.rejected, (state, action) => {
        state.loginSending = false;
      })
      .addCase(doLoginAsync.fulfilled, (state, action) => {
        state.loginSending = false;
      });
  },
});

// Action creators are generated for each case reducer function
export const {
  setApiKey,
  setPassword,
  setAccessKey,
  setSecretKey,
  setInsecure,
  setNavigateTo,
  setFileCertToUpload,
  setFileKeyToUpload,
  resetForm,
} = loginSlice.actions;

// Reducer selectors
export const apiKey = (state: RootState) => state.login.apiKey;
export const password = (state: RootState) => state.login.password;
export const accessKey = (state: RootState) => state.login.accessKey;
export const secretKey = (state: RootState) => state.login.secretKey;
export const insecure = (state: RootState) => state.login.insecure;
export const loginStrategy = (state: RootState) => state.login.loginStrategy;
export const fileCertToUpload = (state: RootState) =>
  state.login.fileCertToUpload;
export const fileKeyToUpload = (state: RootState) =>
  state.login.fileKeyToUpload;

export default loginSlice.reducer;
