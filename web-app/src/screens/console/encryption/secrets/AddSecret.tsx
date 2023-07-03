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
  FormLayout,
  HelpBox,
  HelpIcon,
  InputBox,
  PageHeader,
  PageLayout,
} from "mds";
import { useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../../../../app/hooks";
import { ROUTES } from "../../valid-routes";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import useApi from "../../../../common/hooks/useApi";
import EnclaveSelector from "../EnclaveSelector";

const AddSecret = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const onSuccess = () => navigate(ROUTES.ENCRYPTION_SECRETS);

  const onError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));

  const [loading, invokeApi] = useApi(onSuccess, onError);
  const [secretName, setSecretName] = useState<string>("");
  const [secretValue, setSecretValue] = useState<string>("");
  const enclave = useAppSelector((state) => state.encryption.enclave);

  const addRecord = (event: React.FormEvent) => {
    event.preventDefault();
    invokeApi("POST", `/api/v1/encryption/secrets/?enclave=${enclave}`, {
      secret: secretName,
      value: secretValue,
    });
  };

  const resetForm = () => {
    setSecretName("");
    setSecretValue("");
  };

  const validateSecretName = (secretName: string) => {
    if (secretName.indexOf(" ") !== -1) {
      return "Secret name cannot contain spaces";
    } else return "";
  };

  const validateSecretValue = (secretName: string) => {
    if (secretName.indexOf(" ") !== -1) {
      return "Secret value cannot contain spaces";
    } else return "";
  };

  const validSave =
    secretName.trim() !== "" &&
    secretName.indexOf(" ") === -1 &&
    secretValue.trim() !== "" &&
    secretValue.indexOf(" ") === -1;

  return (
    <Fragment>
      <Grid item xs={12}>
        <PageHeader
          label={
            <BackLink
              label={"Secrets"}
              onClick={() => navigate(ROUTES.ENCRYPTION_SECRETS)}
            />
          }
          actions={<EnclaveSelector />}
        />
        <PageLayout>
          <FormLayout
            title={"Create Secret"}
            icon={<AddAccessRuleIcon />}
            helpBox={
              <HelpBox
                iconComponent={<HelpIcon />}
                title={"Encryption Secret"}
                help={<Fragment>Create a new secret in KES.</Fragment>}
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
                    id="secret-name"
                    name="secret-name"
                    label="Secret Name"
                    autoFocus={true}
                    value={secretName}
                    error={validateSecretName(secretName)}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                      setSecretName(e.target.value);
                    }}
                  />
                </Grid>
                <br />
                <br />
                <br />
                <Grid item xs={12}>
                  <InputBox
                    id="secret-value"
                    name="secret-value"
                    label="Secret Value"
                    autoFocus={true}
                    value={secretValue}
                    type={"password"}
                    error={validateSecretValue(secretValue)}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
                      setSecretValue(e.target.value);
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
                      id={"save-secret"}
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

export default AddSecret;
