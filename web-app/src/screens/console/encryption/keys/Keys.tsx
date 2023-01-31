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

import { Grid, Theme } from "@mui/material";
import { DataTable, Grid as GridMDS, PageHeader, Tooltip } from "mds";

import { createStyles, withStyles } from "@mui/styles";
import { AddIcon, Button, RefreshIcon, UploadIcon } from "mds";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import PageLayout from "../../common/PageLayout";
import SearchBox from "../../common/SearchBox";
import { ROUTES } from "../../valid-routes";
// import withSuspense from "../Common/Components/withSuspense";
// import PageLayout from "../Common/Layout/PageLayout";
// import SearchBox from "../Common/SearchBox";
// import TableWrapper from "../Common/TableWrapper/TableWrapper";

const DeleteModal = React.lazy(() => import("../DeleteModal"));

const styles = (theme: Theme) => createStyles({});

interface IKeysProps {
  classes: any;
}

const ListKeys = ({ classes }: IKeysProps) => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const [filter, setFilter] = useState<string>("");
  const [deleteOpen, setDeleteOpen] = useState<boolean>(false);
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [records, setRecords] = useState<[]>([]);

  // TODO: Use supported apis endpoint to check available apis
  const deleteKey = true;
  const displayKeys = true;

  useEffect(() => {
    fetchRecords();
  }, []);

  useEffect(() => {
    setLoading(true);
  }, [filter]);

  useEffect(() => {
    if (loading) {
      if (displayKeys) {
        let pattern = filter.trim() === "" ? "*" : filter.trim();
        api
          .invoke("GET", `/api/v1/encryption/keys?pattern=${pattern}`)
          .then((res) => {
            setLoading(false);
            setRecords(res.results);
          })
          .catch((err: ErrorResponseHandler) => {
            setLoading(false);
            dispatch(setErrorSnackMessage(err));
          });
      } else {
        setLoading(false);
      }
    }
  }, [loading, setLoading, setRecords, dispatch, displayKeys, filter]);

  const fetchRecords = () => {
    setLoading(true);
  };

  const confirmDeleteKey = (key: string) => {
    console.log("TODO: Delete Key");
    setDeleteOpen(true);
    setSelectedKey(key);
  };

  const closeDeleteModalAndRefresh = (refresh: boolean) => {
    setDeleteOpen(false);

    if (refresh) {
      fetchRecords();
    }
  };

  const tableActions = [
    {
      type: "delete",
      onClick: confirmDeleteKey,
      sendOnlyId: true,
      disableButtonFunction: () => !deleteKey,
    },
  ];

  return (
    <React.Fragment>
      {deleteOpen && (
        <DeleteModal
          deleteOpen={deleteOpen}
          selectedItem={selectedKey}
          endpoint={"/api/v1/encryption/keys/"}
          element={"Key"}
          closeDeleteModalAndRefresh={closeDeleteModalAndRefresh}
        />
      )}
      <PageHeader label="Key Management Service Keys" />
      <PageLayout>
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
            {/* <SecureComponent
              scopes={[IAM_SCOPES.KMS_LIST_KEYS]}
              resource={CONSOLE_UI_RESOURCE}
              errorProps={{ disabled: true }}
            > */}
            <SearchBox
              onChange={setFilter}
              placeholder="Search Keys with pattern"
              value={filter}
            />
            {/* </SecureComponent> */}

            {/* <SecureComponent
              scopes={[IAM_SCOPES.KMS_LIST_KEYS]}
              resource={CONSOLE_UI_RESOURCE}
              errorProps={{ disabled: true }}
            > */}
            <Tooltip placement="bottom" tooltip={"Refresh"}>
              <Button
                id={"refresh-keys"}
                variant="regular"
                icon={<RefreshIcon />}
                onClick={() => setLoading(true)}
              />
            </Tooltip>
            {/* </SecureComponent> */}
            {/* <SecureComponent
              scopes={[IAM_SCOPES.KMS_IMPORT_KEY]}
              resource={CONSOLE_UI_RESOURCE}
              errorProps={{ disabled: true }}
            > */}
            <Tooltip placement="bottom" tooltip={"Import Key"}>
              <Button
                id={"import-key"}
                variant={"regular"}
                icon={<UploadIcon />}
                onClick={() => {
                  navigate(ROUTES.ENCRYPTION_KEYS_IMPORT);
                }}
              />
            </Tooltip>
            {/* </SecureComponent> */}
            {/* <SecureComponent
              scopes={[IAM_SCOPES.KMS_CREATE_KEY]}
              resource={CONSOLE_UI_RESOURCE}
              errorProps={{ disabled: true }}
            > */}
            <Tooltip placement="bottom" tooltip={"Create Key"}>
              <Button
                id={"create-key"}
                label={"Create Key"}
                variant={"callAction"}
                icon={<AddIcon />}
                onClick={() => navigate(ROUTES.ENCRYPTION_KEYS_ADD)}
              />
            </Tooltip>
            {/* </SecureComponent> */}
          </Grid>
          <Grid item xs={12}>
            {/* <SecureComponent
              scopes={[IAM_SCOPES.KMS_LIST_KEYS]}
              resource={CONSOLE_UI_RESOURCE}
              errorProps={{ disabled: true }}
            > */}
            <GridMDS item xs={12}>
              <DataTable
                itemActions={tableActions}
                columns={[
                  {
                    label: "Name",
                    elementKey: "name",
                  },
                  {
                    label: "Created by",
                    elementKey: "createdBy",
                  },
                  {
                    label: "Created at",
                    elementKey: "createdAt",
                  },
                ]}
                entityName="keys"
                records={records}
              />
            </GridMDS>
            {/* </SecureComponent> */}
          </Grid>
        </Grid>
      </PageLayout>
    </React.Fragment>
  );
};

export default withStyles(styles)(ListKeys);
