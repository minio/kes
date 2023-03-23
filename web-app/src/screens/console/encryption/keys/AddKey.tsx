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
import {
  AddAccessRuleIcon,
  BackLink,
  Button,
  HelpBox,
  PageHeader,
  HelpIcon,
  FormLayout,
  InputBox,
  PageLayout,
} from "mds";
import { useNavigate } from "react-router-dom";
import { useAppDispatch } from "../../../../app/hooks";
import { ROUTES } from "../../valid-routes";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import useApi from "../../../../common/hooks/useApi";

const AddKey = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const onSuccess = () => navigate(ROUTES.ENCRYPTION_KEYS);

  const onError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));

  const [loading, invokeApi] = useApi(onSuccess, onError);
  const [keyName, setKeyName] = useState<string>("");

  const addRecord = (event: React.FormEvent) => {
    event.preventDefault();
    invokeApi("POST", "/api/v1/encryption/keys/", { key: keyName });
  };

  const resetForm = () => {
    setKeyName("");
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
            title={"Create Key"}
            icon={<AddAccessRuleIcon />}
            helpBox={
              <HelpBox
                iconComponent={<HelpIcon />}
                title={"Encryption Key"}
                help={
                  <Fragment>Create a new cryptographic key in KES.</Fragment>
                }
              />
            }
          >
            <form
              noValidate
              autoComplete="off"
              onSubmit={(e: React.FormEvent<HTMLFormElement>) => {
                addRecord(e);
              }}
            >
              <Grid container item spacing={1}>
                <Grid item xs={12}>
                  <InputBox
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
                      id={"save-key"}
                      type="submit"
                      variant="callAction"
                      color="primary"
                      disabled={loading || !validSave}
                      label={"Save"}
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

export default AddKey;
