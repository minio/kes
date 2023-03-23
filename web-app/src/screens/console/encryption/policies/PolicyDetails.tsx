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

import React, { Fragment, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  PageHeader,
  BackLink,
  IAMPoliciesIcon,
  Tooltip,
  Button,
  TrashIcon,
  RefreshIcon,
  DataTable,
  PageLayout,
  SectionTitle,
} from "mds";
import { Theme } from "@mui/material/styles";
import createStyles from "@mui/styles/createStyles";
import withStyles from "@mui/styles/withStyles";
import Grid from "@mui/material/Grid";
import { useAppDispatch } from "../../../../app/hooks";
import {
  setErrorSnackMessage,
  setSnackBarMessage,
} from "../../../../systemSlice";
import { ErrorResponseHandler } from "../../../../common/api/types";
import useApi from "../../../../common/hooks/useApi";

// import PolicyDetailsPanel from "./PolicyDetailsPanel";
import { EncryptionPolicy } from "../types";
import api from "../../../../common/api";
import { ROUTES } from "../../valid-routes";
import ScreenTitle from "../../common/ScreenTitle";
import VerticalTabs from "../../common/VerticalTabs";
import PolicyDetailsPanel from "./PolicyDetailsPanel";
import SearchBox from "../../common/SearchBox";
import CodeMirrorWrapper from "../../common/CodeMirrorWrapper";
import { Box } from "@mui/material";

const styles = (theme: Theme) =>
  createStyles({
    pageContainer: {
      border: "1px solid #EAEAEA",
      height: "100%",
    },
  });

interface IPolicyDetailsProps {
  classes: any;
}

const DeleteModal = React.lazy(() => import("../DeleteModal"));

const decodeURLString = (text: string) => {
  try {
    return decodeURIComponent(escape(window.atob(text)));
  } catch (err) {
    return text;
  }
};

const PolicyDetails = ({ classes }: IPolicyDetailsProps) => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const params = useParams();
  const policyName = decodeURLString(params.policyName || "");

  const onAssignPolicySuccess = () =>
    dispatch(setSnackBarMessage("Policy successfully assigned"));

  const onAssignPolicyError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));

  const [assignPolicyloading, invokeAssignPolicyApi] = useApi(
    onAssignPolicySuccess,
    onAssignPolicyError
  );

  const onSavePolicySuccess = () =>
    dispatch(setSnackBarMessage("Policy successfully updated"));

  const onSavePolicyError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));

  const [addLoading, invokeApi] = useApi(
    onSavePolicySuccess,
    onSavePolicyError
  );
  const [policy, setPolicy] = useState<EncryptionPolicy | null>(null);
  const [loadingPolicy, setLoadingPolicy] = useState<boolean>(true);

  const [identities, setIdentities] = useState<[]>([]);
  const [identitiesFilter, setIdentitiesFilter] = useState<string>("");
  const [loadingIdentities, setLoadingIdentities] = useState<boolean>(true);
  const [policyDefinition, setPolicyDefinition] = useState<string>("");

  const [deleteOpen, setDeleteOpen] = useState<boolean>(false);

  // TODO: Use supported apis endpoint to check available apis
  const displayIdentities = true;
  const displayPolicy = true;
  const editPolicy = true;

  useEffect(() => {
    setLoadingIdentities(true);
  }, [identitiesFilter]);

  useEffect(() => {
    const loadIdentities = () => {
      if (displayIdentities) {
        let pattern =
          identitiesFilter.trim() === "" ? "*" : identitiesFilter.trim();
        api
          .invoke("GET", `/api/v1/encryption/identities?pattern=${pattern}`)
          .then((result: any) => {
            setIdentities(result.results);
            setLoadingIdentities(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingIdentities(false);
          });
      } else {
        setLoadingIdentities(false);
      }
    };

    const loadPolicyDetails = () => {
      if (displayPolicy) {
        api
          .invoke("GET", `/api/v1/encryption/policies/${policyName}`)
          .then((result: any) => {
            if (result) {
              setPolicy(result);
              setPolicyDefinition(JSON.stringify(result, null, 4));
            }
            setLoadingPolicy(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingPolicy(false);
          });
      } else {
        setLoadingPolicy(false);
      }
    };

    if (loadingPolicy) {
      loadPolicyDetails();
    }
    if (loadingIdentities) {
      loadIdentities();
    }
  }, [
    dispatch,
    displayPolicy,
    loadingPolicy,
    policyName,
    displayIdentities,
    loadingIdentities,
    identitiesFilter,
  ]);

  const savePolicy = (event: React.FormEvent) => {
    event.preventDefault();
    let data = JSON.parse(policyDefinition);
    data["policy"] = policyName;
    invokeApi("POST", "/api/v1/encryption/policies/", data);
  };

  const identitiesTableActions = [
    {
      type: "share",
      label: "Assign Identity",
      onClick: (identity: string) => {
        invokeAssignPolicyApi(
          "POST",
          `/api/v1/encryption/policies/${policyName}/assign`,
          { identity }
        );
      },
      sendOnlyId: true,
    },
  ];

  const deletePolicy = () => {
    setDeleteOpen(true);
  };

  const closeDeleteModalAndRefresh = (refresh: boolean) => {
    setDeleteOpen(false);

    if (refresh) {
      navigate(ROUTES.ENCRYPTION_POLICIES);
    }
  };

  return (
    <Fragment>
      {deleteOpen && (
        <DeleteModal
          withWarning={false}
          deleteOpen={deleteOpen}
          selectedItem={policyName}
          endpoint={"/api/v1/encryption/policies/"}
          element={"Policy"}
          label={"Delete Policy"}
          closeDeleteModalAndRefresh={closeDeleteModalAndRefresh}
        />
      )}
      <PageHeader
        label={
          <BackLink
            label={"Policies"}
            onClick={() => navigate(ROUTES.ENCRYPTION_KEYS)}
          />
        }
      />

      <PageLayout className={classes.pageContainer}>
        <Grid item xs={12}>
          <ScreenTitle
            icon={
              <Fragment>
                <IAMPoliciesIcon width={40} />
              </Fragment>
            }
            title={policyName}
            subTitle={<Fragment>KES Policy</Fragment>}
            actions={
              <Fragment>
                {/* <SecureComponent
                  scopes={[IAM_SCOPES.KMS_DELETE_POLICY]}
                  resource={CONSOLE_UI_RESOURCE}
                  errorProps={{ disabled: true }}
                > */}

                <Tooltip placement="bottom" tooltip={"Delete Policy"}>
                  <Button
                    id={"delete-policy"}
                    label={"Delete Policy"}
                    variant="secondary"
                    icon={<TrashIcon />}
                    onClick={deletePolicy}
                  />
                </Tooltip>
                {/* </SecureComponent> */}

                <Tooltip placement="bottom" tooltip={"Refresh"}>
                  <Button
                    id={"refresh-policy"}
                    label={"Refresh"}
                    variant="regular"
                    icon={<RefreshIcon />}
                    onClick={() => {
                      setLoadingPolicy(true);
                      setLoadingIdentities(true);
                    }}
                  />
                </Tooltip>
              </Fragment>
            }
          />
        </Grid>

        <VerticalTabs>
          {{
            tabConfig: { label: "Summary", disabled: !displayPolicy },
            content: (
              <Fragment>
                <SectionTitle>Summary</SectionTitle>
                {policy && (
                  <PolicyDetailsPanel
                    allow={policy.allow || []}
                    deny={policy.deny || []}
                  />
                )}
              </Fragment>
            ),
          }}
          {{
            tabConfig: {
              label: "Assign to Identities",
              disabled: !displayIdentities,
            },
            content: (
              <Fragment>
                <SectionTitle>Assign Identity</SectionTitle>
                <Grid container spacing={1}>
                  <Grid
                    item
                    xs={12}
                    display={"flex"}
                    alignItems={"center"}
                    justifyContent={"flex-end"}
                    sx={{
                      "& button": {
                        marginLeft: "8px",
                      },
                    }}
                  >
                    <SearchBox
                      onChange={setIdentitiesFilter}
                      placeholder="Search Identities with pattern"
                      value={identitiesFilter}
                    />
                  </Grid>
                  <Grid item xs={12} className={classes.tableBlock}>
                    {/* <SecureComponent
                      scopes={[IAM_SCOPES.KMS_LIST_KEYS]}
                      resource={CONSOLE_UI_RESOURCE}
                      errorProps={{ disabled: true }}
                    > */}
                    <DataTable
                      itemActions={identitiesTableActions}
                      columns={[
                        { label: "Identity", elementKey: "identity" },
                        { label: "Policy", elementKey: "policy" },
                      ]}
                      isLoading={loadingIdentities || assignPolicyloading}
                      records={identities}
                      entityName="Identities"
                      idField="identity"
                    />
                    {/* </SecureComponent> */}
                  </Grid>
                </Grid>
              </Fragment>
            ),
          }}
          {{
            tabConfig: { label: "Raw Policy", disabled: !displayPolicy },
            content: (
              <Fragment>
                <SectionTitle>Raw Policy</SectionTitle>
                <form
                  noValidate
                  autoComplete="off"
                  onSubmit={(e: React.FormEvent<HTMLFormElement>) => {
                    savePolicy(e);
                  }}
                >
                  <Grid container>
                    <Grid item xs={12}>
                      <CodeMirrorWrapper
                        readOnly={!editPolicy}
                        value={policyDefinition}
                        onBeforeChange={(editor, data, value) => {
                          setPolicyDefinition(value);
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
                        {!policy && (
                          <Button
                            id={"clear"}
                            type="button"
                            variant="regular"
                            onClick={() => setPolicyDefinition("")}
                            label={"Clear"}
                          />
                        )}
                        {/* <SecureComponent
                        scopes={[IAM_SCOPES.KMS_SET_POLICY]}
                        resource={CONSOLE_UI_RESOURCE}
                        errorProps={{ disabled: true }}
                      > */}
                        <Button
                          id={"save"}
                          type="submit"
                          variant="callAction"
                          color="primary"
                          disabled={addLoading}
                          label={"Save"}
                        />
                      </Box>
                      {/* </SecureComponent> */}
                    </Grid>
                  </Grid>
                </form>
              </Fragment>
            ),
          }}
        </VerticalTabs>
      </PageLayout>
    </Fragment>
  );
};

export default withStyles(styles)(PolicyDetails);
