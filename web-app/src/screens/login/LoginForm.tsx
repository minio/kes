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
import React, { Fragment, useRef } from "react";
import { Button, UploadIcon } from "mds";
import {
  Checkbox,
  FormControlLabel,
  InputAdornment,
  LinearProgress,
} from "@mui/material";
import { LockFilledIcon } from "mds";
import makeStyles from "@mui/styles/makeStyles";
import { Theme } from "@mui/material/styles";
import createStyles from "@mui/styles/createStyles";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { LoginField } from "./LoginField";
import {
  setFileCertToUpload,
  setFileKeyToUpload,
  setInsecure,
  setIsEncrypted,
  setPassword,
} from "./loginSlice";
import { doLoginAsync } from "./loginThunks";

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

  const fileCert = useRef<HTMLInputElement>(null);
  const fileKey = useRef<HTMLInputElement>(null);

  const formSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    dispatch(doLoginAsync());
  };

  const disableLogin = () => {
    if (fileCertToUpload === null || fileKeyToUpload === null) {
      return true;
    }
    if (isEncrypted && !password) {
      return true;
    }
    return false;
  };

  const handleFileCert = (e: any) => {
    if (
      e === null ||
      e === undefined ||
      e.target.files === null ||
      e.target.files === undefined
    ) {
      return;
    }
    e.preventDefault();
    const [fileToUpload] = e.target.files;
    const blobFile = new Blob([fileToUpload], { type: fileToUpload.type });
    e.target.value = "";
    dispatch(setFileCertToUpload(blobFile));
  };

  const handleFileKey = (e: any) => {
    if (
      e === null ||
      e === undefined ||
      e.target.files === null ||
      e.target.files === undefined
    ) {
      return;
    }
    e.preventDefault();
    const [fileToUpload] = e.target.files;
    const blobFile = new Blob([fileToUpload], { type: fileToUpload.type });
    e.target.value = "";
    dispatch(setFileKeyToUpload(blobFile));
  };

  return (
    <React.Fragment>
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
        <Grid item xs={12}>
          <Fragment>
            <input
              type="file"
              onChange={handleFileCert}
              style={{ display: "none" }}
              ref={fileCert}
            />
            <Button
              id={"upload-cert"}
              onClick={(e) => {
                e.preventDefault();
                if (fileCert && fileCert.current) {
                  fileCert.current.click();
                }
              }}
              icon={<UploadIcon />}
              label={`Upload KES Client Certificate${
                fileCertToUpload ? ` (${fileCertToUpload.size})` : ""
              }`}
              variant={"regular"}
              fullWidth
            />
          </Fragment>
        </Grid>
        <br />
        <Grid item xs={12}>
          <Fragment>
            <input
              type="file"
              onChange={handleFileKey}
              style={{ display: "none" }}
              ref={fileKey}
            />
            <Button
              id={"upload-key"}
              onClick={(e) => {
                e.preventDefault();
                if (fileKey && fileKey.current) {
                  fileKey.current.click();
                }
              }}
              icon={<UploadIcon />}
              label={`Upload KES Client Key${
                fileKeyToUpload ? ` (${fileKeyToUpload.size})` : ""
              }`}
              variant={"regular"}
              fullWidth
            />
          </Fragment>
        </Grid>
        {isEncrypted && (
          <Grid item xs={12}>
            <br />
            <LoginField
              fullWidth
              value={password}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                dispatch(setPassword(e.target.value))
              }
              name="secretKey"
              type="password"
              id="secretKey"
              autoComplete="current-password"
              disabled={loginSending}
              placeholder={"Password"}
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
        )}

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
        <Grid item xs={12} className={classes.linearPredef}>
          {loginSending && <LinearProgress />}
        </Grid>
      </form>
    </React.Fragment>
  );
};

export default LoginForm;
