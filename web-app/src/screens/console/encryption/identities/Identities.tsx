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
  Button,
  DataTable,
  Grid as GridMDS,
  PageHeader,
  PageLayout,
  RefreshIcon,
  Tooltip,
} from "mds";
import React, { useEffect, useState } from "react";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import SearchBox from "../../common/SearchBox";

const DeleteModal = React.lazy(() => import("../DeleteModal"));

const ListIdentities = () => {
  const dispatch = useAppDispatch();
  const [filter, setFilter] = useState<string>("");
  const [deleteOpen, setDeleteOpen] = useState<boolean>(false);
  const [selectedIdentity, setSelectedIdentity] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [records, setRecords] = useState<[]>([]);

  // TODO: Use supported apis endpoint to check available apis
  const deleteIdentity = true;
  const displayIdentities = true;

  useEffect(() => {
    fetchRecords();
  }, []);

  useEffect(() => {
    setLoading(true);
  }, [filter]);

  useEffect(() => {
    if (loading) {
      if (displayIdentities) {
        let pattern = filter.trim() === "" ? "*" : filter.trim();
        api
          .invoke("GET", `/api/v1/encryption/identities?pattern=${pattern}`)
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
  }, [loading, setLoading, setRecords, dispatch, displayIdentities, filter]);

  const fetchRecords = () => {
    setLoading(true);
  };

  const confirmDeleteIdentity = (identity: string) => {
    setDeleteOpen(true);
    setSelectedIdentity(identity);
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
      onClick: confirmDeleteIdentity,
      sendOnlyId: true,
      disableButtonFunction: () => !deleteIdentity,
    },
  ];

  return (
    <React.Fragment>
      {deleteOpen && (
        <DeleteModal
          deleteOpen={deleteOpen}
          withWarning={false}
          selectedItem={selectedIdentity}
          endpoint={"/api/v1/encryption/identities/"}
          element={"Identity"}
          label={"Delete Identity"}
          closeDeleteModalAndRefresh={closeDeleteModalAndRefresh}
        />
      )}
      <PageHeader label="Identities" />
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
              placeholder="Search Identities with pattern"
              value={filter}
            />
            <Tooltip placement="bottom" tooltip={"Refresh"}>
              <Button
                id={"refresh-identities"}
                variant="regular"
                icon={<RefreshIcon />}
                onClick={() => setLoading(true)}
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
                entityName="identities"
                records={records}
                idField="identity"
              />
            </GridMDS>
          </Grid>
        </Grid>
      </PageLayout>
    </React.Fragment>
  );
};

export default ListIdentities;
