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

import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { RootState } from "../../../app/store";

const initSideBarOpen = localStorage.getItem("sidebarOpen")
  ? JSON.parse(localStorage.getItem("sidebarOpen")!)["open"]
  : true;

export interface EncryptionState {
  enclave: string;
}

const initialState: EncryptionState = {
  enclave: "default",
};

export const encryptionSlice = createSlice({
  name: "encryption",
  initialState,
  reducers: {
    setEnclave: (state, action: PayloadAction<string>) => {
      state.enclave = action.payload;
    },
  },
});

// Reducer actions
export const { setEnclave } = encryptionSlice.actions;

// Reducer selectors
export const enclave = (state: RootState) => state.encryption.enclave;

export default encryptionSlice.reducer;
