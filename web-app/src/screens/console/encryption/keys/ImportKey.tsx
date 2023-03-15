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

import React, { Fragment, useState } from "react";
import { Box } from "@mui/material";

import Grid from "@mui/material/Grid";
import { AddAccessRuleIcon, BackLink, Button, PageHeader } from "mds";
import { useNavigate } from "react-router-dom";
import { useAppDispatch } from "../../../../app/hooks";
import { ROUTES } from "../../valid-routes";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import useApi from "../../../../common/hooks/useApi";
import PageLayout from "../../common/PageLayout";
import FormLayout from "../../common/FormLayout";
import HelpBox from "../../common/Helpbox";
import CodeMirrorWrapper from "../../common/CodeMirrorWrapper";
import InputBoxWrapper from "../../common/InputBoxWrapper";

export const emptyContent = '{\n    "bytes": ""\n}';

const ImportKey = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const onSuccess = () => navigate(ROUTES.ENCRYPTION_KEYS);

  const onError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));

  const [loading, invokeApi] = useApi(onSuccess, onError);
  const [keyName, setKeyName] = useState<string>("");
  const [keyContent, setKeyContent] = useState<string>(emptyContent);

  const importRecord = (event: React.FormEvent) => {
    event.preventDefault();
    let data = JSON.parse(keyContent);
    invokeApi("POST", `/api/v1/encryption/keys/${keyName}/import`, data);
  };

  const resetForm = () => {
    setKeyName("");
    setKeyContent("");
  };

  const validateKeyName = (keyName: string) => {
    if (keyName.indexOf(" ") !== -1) {
      return "Key name cannot contain spaces";
    } else return "";
  };

  const validSave = keyName.trim() !== "" && keyName.indexOf(" ") === -1;

  return (
    <Fragment>
      <Grid item xs={12}>
        <PageHeader
          label={
            <BackLink
              label={"Keys"}
              onClick={() => navigate(ROUTES.ENCRYPTION_KEYS)}
            />
          }
        />
        <PageLayout>
          <FormLayout
            title={"Import Key"}
            icon={<AddAccessRuleIcon />}
            helpbox={
              <HelpBox
                helpText={"Encryption Key"}
                contents={["Import a cryptographic key in KES."]}
              />
            }
          >
            <form
              noValidate
              autoComplete="off"
              onSubmit={(e: React.FormEvent<HTMLFormElement>) => {
                importRecord(e);
              }}
            >
              <Grid container item spacing={1}>
                <Grid item xs={12}>
                  <InputBoxWrapper
                    id="key-name"
                    name="key-name"
                    label="Key Name"
                    autoFocus={true}
                    value={keyName}
                    error={validateKeyName(keyName)}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                      setKeyName(e.target.value);
                    }}
                  />
                </Grid>
                <Grid item xs={12}>
                  <CodeMirrorWrapper
                    label={"Set key Content"}
                    value={keyContent}
                    onBeforeChange={(editor, data, value) => {
                      setKeyContent(value);
                    }}
                    editorHeight={"350px"}
                  />
                </Grid>
                <Grid item xs={12} textAlign={"right"}>
                  <Box
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "flex-end",
                      marginTop: "20px",
                      gap: "15px",
                    }}
                  >
                    <Button
                      id={"clear"}
                      type="button"
                      variant="regular"
                      onClick={resetForm}
                      label={"Clear"}
                    />

                    <Button
                      id={"import-key"}
                      type="submit"
                      variant="callAction"
                      color="primary"
                      disabled={loading || !validSave}
                      label={"Import"}
                    />
                  </Box>
                </Grid>
              </Grid>
            </form>
          </FormLayout>
        </PageLayout>
      </Grid>
    </Fragment>
  );
};

export default ImportKey;
