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

import { Grid } from "@mui/material";
import {
  AddIcon,
  Button,
  DataTable,
  Grid as GridMDS,
  PageHeader,
  RefreshIcon,
  Tooltip,
} from "mds";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import PageLayout from "../../common/PageLayout";
import SearchBox from "../../common/SearchBox";
import { ROUTES } from "../../valid-routes";

const DeleteKMSModal = React.lazy(() => import("../DeleteModal"));

const ListPolicies = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [filter, setFilter] = useState<string>("");
  const [deleteOpen, setDeleteOpen] = useState<boolean>(false);
  const [selectedPolicy, setSelectedPolicy] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [records, setRecords] = useState<[]>([]);

  // TODO: Use supported apis endpoint to check available apis
  const deletePolicy = true;
  const displayPolicies = true;
  const viewPolicy = true;

  useEffect(() => {
    fetchRecords();
  }, []);

  useEffect(() => {
    setLoading(true);
  }, [filter]);

  useEffect(() => {
    if (loading) {
      if (displayPolicies) {
        let pattern = filter.trim() === "" ? "*" : filter.trim();
        api
          .invoke("GET", `/api/v1/encryption/policies?pattern=${pattern}`)
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
  }, [loading, setLoading, setRecords, dispatch, displayPolicies, filter]);

  const fetchRecords = () => {
    setLoading(true);
  };

  const confirmDeletePolicy = (policy: string) => {
    setDeleteOpen(true);
    setSelectedPolicy(policy);
  };

  const closeDeleteModalAndRefresh = (refresh: boolean) => {
    setDeleteOpen(false);

    if (refresh) {
      fetchRecords();
    }
  };

  const tableActions = [
    {
      type: "view",
      onClick: (policy: any) =>
        navigate(`${ROUTES.ENCRYPTION_POLICIES}/${policy.name}`),
      disableButtonFunction: () => !viewPolicy,
    },
    {
      type: "delete",
      onClick: confirmDeletePolicy,
      sendOnlyId: true,
      disableButtonFunction: () => !deletePolicy,
    },
  ];

  return (
    <React.Fragment>
      {deleteOpen && (
        <DeleteKMSModal
          deleteOpen={deleteOpen}
          withWarning={false}
          selectedItem={selectedPolicy}
          endpoint={"/api/v1/kms/policies/"}
          element={"Policy"}
          label={"Delete Policy"}
          closeDeleteModalAndRefresh={closeDeleteModalAndRefresh}
        />
      )}
      <PageHeader label="Policies" />
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
            <SearchBox
              onChange={setFilter}
              placeholder="Search Policies with pattern"
              value={filter}
            />
            <Tooltip placement="bottom" tooltip={"Refresh"}>
              <Button
                id={"refresh-policies"}
                variant="regular"
                icon={<RefreshIcon />}
                onClick={() => setLoading(true)}
              />
            </Tooltip>
            <Tooltip placement="bottom" tooltip={"Create Policy"}>
              <Button
                id={"create-policy"}
                label={"Create policy"}
                variant={"callAction"}
                icon={<AddIcon />}
                onClick={() => navigate(ROUTES.ENCRYPTION_POLICIES_ADD)}
              />
            </Tooltip>
          </Grid>
          <Grid item xs={12}>
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
                entityName="policies"
                records={records}
                idField={"name"}
              />
            </GridMDS>
          </Grid>
        </Grid>
      </PageLayout>
    </React.Fragment>
  );
};

export default ListPolicies;
