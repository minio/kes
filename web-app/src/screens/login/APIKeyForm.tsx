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

import { Grid, InputAdornment } from "@mui/material";
import { LockFilledIcon } from "mds";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { LoginField } from "./LoginField";
import { setApiKey } from "./loginSlice";

const APIKeyForm = () => {
  const dispatch = useAppDispatch();
  const apiKey = useAppSelector((state) => state.login.apiKey);
  const loginSending = useAppSelector((state) => state.login.loginSending);
  return (
    <Grid item xs={12}>
      <LoginField
        fullWidth
        value={apiKey}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
          dispatch(setApiKey(e.target.value))
        }
        name="api-key"
        id="api-key"
        disabled={loginSending}
        placeholder={"API Key"}
        variant={"outlined"}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <LockFilledIcon />
            </InputAdornment>
          ),
        }}
      />
    </Grid>
  );
};

export default APIKeyForm;
