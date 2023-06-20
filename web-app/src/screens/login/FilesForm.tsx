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
import { Button, LockFilledIcon, UploadIcon } from "mds";
import { Fragment, useRef } from "react";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { LoginField } from "./LoginField";
import {
  setFileCertToUpload,
  setFileKeyToUpload,
  setPassword,
} from "./loginSlice";

const FilesForm = () => {
  const dispatch = useAppDispatch();

  const password = useAppSelector((state) => state.login.password);
  const loginSending = useAppSelector((state) => state.login.loginSending);
  const fileCertToUpload = useAppSelector(
    (state) => state.login.fileCertToUpload
  );
  const fileKeyToUpload = useAppSelector(
    (state) => state.login.fileKeyToUpload
  );

  const fileCert = useRef<HTMLInputElement>(null);
  const fileKey = useRef<HTMLInputElement>(null);

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
    <>
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
    </>
  );
};

export default FilesForm;
