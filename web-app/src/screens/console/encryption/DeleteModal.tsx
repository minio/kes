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

import React, { useState } from "react";

import { DialogContentText } from "@mui/material";
import { useAppDispatch } from "../../../app/hooks";
import { ErrorResponseHandler } from "../../../common/api/types";
import { setErrorSnackMessage } from "../../../systemSlice";
import useApi from "../../../common/hooks/useApi";
import { ConfirmDeleteIcon, Grid } from "mds";
import InputBoxWrapper from "../common/InputBoxWrapper";
import ConfirmDialog from "../common/ConfirmDialog";
import WarningMessage from "../WarningMessage";

interface IDeleteModalProps {
  closeDeleteModalAndRefresh: (refresh: boolean) => void;
  deleteOpen: boolean;
  withWarning: boolean;
  selectedItem: string;
  endpoint: string;
  element: string;
  label: string;
}

const DeleteModal = ({
  closeDeleteModalAndRefresh,
  deleteOpen,
  withWarning,
  selectedItem,
  endpoint,
  element,
  label,
}: IDeleteModalProps) => {
  const dispatch = useAppDispatch();
  const onDelSuccess = () => closeDeleteModalAndRefresh(true);
  const onDelError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));
  const onClose = () => closeDeleteModalAndRefresh(false);

  const [deleteLoading, invokeDeleteApi] = useApi(onDelSuccess, onDelError);
  const [retype, setRetype] = useState("");

  if (!selectedItem) {
    return null;
  }

  const onConfirmDelete = () => {
    invokeDeleteApi("DELETE", `${endpoint}${selectedItem}`);
  };

  return (
    <ConfirmDialog
      title={`Delete ${element}`}
      confirmText={"Delete"}
      isOpen={deleteOpen}
      titleIcon={<ConfirmDeleteIcon />}
      isLoading={deleteLoading}
      onConfirm={onConfirmDelete}
      onClose={onClose}
      confirmButtonProps={{
        disabled: retype !== selectedItem || deleteLoading,
      }}
      confirmationContent={
        <DialogContentText>
          {withWarning && (
            <Grid item xs={12}>
              <WarningMessage title={"WARNING"} label={label} />
            </Grid>
          )}
          To continue please type <b>{selectedItem}</b> in the box.
          <Grid item xs={12}>
            <InputBoxWrapper
              id="retype-key"
              name="retype-key"
              onChange={(event: React.ChangeEvent<HTMLInputElement>) => {
                setRetype(event.target.value);
              }}
              label=""
              value={retype}
            />
          </Grid>
        </DialogContentText>
      }
    />
  );
};

export default DeleteModal;
