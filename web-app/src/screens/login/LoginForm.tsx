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

import Grid from "@mui/material/Grid";
import React, { Fragment, useState } from "react";
import { Button } from "mds";
import {
  Checkbox,
  FormControlLabel,
  InputAdornment,
  LinearProgress,
  MenuItem,
  Select,
  SelectChangeEvent,
} from "@mui/material";
import makeStyles from "@mui/styles/makeStyles";
import { Theme } from "@mui/material/styles";
import createStyles from "@mui/styles/createStyles";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { LoginField } from "./LoginField";
import {
  setApiKey,
  setFileCertToUpload,
  setFileKeyToUpload,
  setInsecure,
  setIsEncrypted,
  setPassword,
} from "./loginSlice";
import { doLoginAsync } from "./loginThunks";
import APIKeyForm from "./APIKeyForm";
import FilesForm from "./FilesForm";

const useStyles = makeStyles((theme: Theme) =>
  createStyles({
    root: {
      position: "absolute",
      top: 0,
      left: 0,
      width: "100%",
      height: "100%",
      overflow: "auto",
    },
    form: {
      width: "100%", // Fix IE 11 issue.
    },
    submit: {
      margin: "30px 0px 8px",
      height: 40,
      width: "100%",
      boxShadow: "none",
      padding: "16px 30px",
    },
    submitContainer: {
      textAlign: "right",
      marginTop: 30,
    },
    linearPredef: {
      height: 10,
    },
  })
);

const LoginForm = () => {
  const dispatch = useAppDispatch();
  const classes = useStyles();

  const [loginStrategy, setLoginStrategy] = useState("apiKey");

  const password = useAppSelector((state) => state.login.password);
  const loginSending = useAppSelector((state) => state.login.loginSending);
  const insecure = useAppSelector((state) => state.login.insecure);
  const isEncrypted = useAppSelector((state) => state.login.isEncrypted);

  const fileCertToUpload = useAppSelector(
    (state) => state.login.fileCertToUpload
  );
  const fileKeyToUpload = useAppSelector(
    (state) => state.login.fileKeyToUpload
  );
  const apiKey = useAppSelector((state) => state.login.apiKey);

  const formSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    dispatch(doLoginAsync());
  };

  const disableLogin = () => {
    if (loginStrategy === "apiKey" && !apiKey) {
      return true;
    }
    if (
      loginStrategy !== "apiKey" &&
      (fileCertToUpload === null || fileKeyToUpload === null)
    ) {
      return true;
    }
    if (isEncrypted && !password) {
      return true;
    }
    return false;
  };

  const changeLoginStrategy = (e: SelectChangeEvent<string>) => {
    dispatch(setFileCertToUpload(null));
    dispatch(setFileKeyToUpload(null));
    dispatch(setApiKey(""));
    setLoginStrategy(e.target.value);
  };

  return (
    <Fragment>
      <form className={classes.form} noValidate onSubmit={formSubmit}>
        <Grid item xs={12}>
          <FormControlLabel
            label="Insecure"
            control={
              <Checkbox
                checked={insecure}
                onChange={(e) => dispatch(setInsecure(e.target.checked))}
              />
            }
          />
          <FormControlLabel
            label="Is Encrypted"
            control={
              <Checkbox
                checked={isEncrypted}
                onChange={(e) => {
                  dispatch(setIsEncrypted(e.target.checked));
                  dispatch(setPassword(""));
                }}
              />
            }
          />
        </Grid>
        <br />
        {loginStrategy === "apiKey" ? <APIKeyForm /> : <FilesForm />}
        <Grid item xs={12} className={classes.submitContainer}>
          <Button
            type="submit"
            variant="callAction"
            color="primary"
            id="do-login"
            className={classes.submit}
            disabled={disableLogin()}
            label={"Login"}
            fullWidth
          />
        </Grid>
        <br />
        <Select
          id="login-select-strategy"
          name="login-select-strategy"
          value={loginStrategy}
          onChange={changeLoginStrategy}
          sx={{
            width: "100%",
            height: "38px",
            fontSize: "14px",
            borderRadius: "4px",
          }}
        >
          <MenuItem value={"apiKey"}>{"API Key"}</MenuItem>
          <MenuItem value={"files"}>{"Client Files"}</MenuItem>
        </Select>
        <Grid item xs={12} className={classes.linearPredef}>
          {loginSending && <LinearProgress />}
        </Grid>
      </form>
    </Fragment>
  );
};

export default LoginForm;
