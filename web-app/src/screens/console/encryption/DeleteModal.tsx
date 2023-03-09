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

import React from "react";

import { DialogContentText } from "@mui/material";
import { useAppDispatch } from "../../../app/hooks";
import { ErrorResponseHandler } from "../../../common/api/types";
import { setErrorSnackMessage } from "../../../systemSlice";
import useApi from "../../../common/hooks/useApi";
// import ConfirmDialog from "../Common/ModalWrapper/ConfirmDialog";

interface IDeleteModalProps {
  closeDeleteModalAndRefresh: (refresh: boolean) => void;
  deleteOpen: boolean;
  selectedItem: string;
  endpoint: string;
  element: string;
}

const DeleteModal = ({
  closeDeleteModalAndRefresh,
  deleteOpen,
  selectedItem,
  endpoint,
  element,
}: IDeleteModalProps) => {
  const dispatch = useAppDispatch();
  const onDelSuccess = () => closeDeleteModalAndRefresh(true);
  const onDelError = (err: ErrorResponseHandler) =>
    dispatch(setErrorSnackMessage(err));
  const onClose = () => closeDeleteModalAndRefresh(false);

  const [deleteLoading, invokeDeleteApi] = useApi(onDelSuccess, onDelError);
  if (!selectedItem) {
    return null;
  }

  const onConfirmDelete = () => {
    invokeDeleteApi("DELETE", `${endpoint}${selectedItem}`);
  };

  return (
    <h1>TODO: Implement dialog</h1>
    // <ConfirmDialog
    //   title={`Delete ${element}`}
    //   confirmText={"Delete"}
    //   isOpen={deleteOpen}
    //   titleIcon={<ConfirmDeleteIcon />}
    //   isLoading={deleteLoading}
    //   onConfirm={onConfirmDelete}
    //   onClose={onClose}
    //   confirmationContent={
    //     <DialogContentText>
    //       Are you sure you want to delete this element <br />
    //       <b>{selectedItem}</b>?
    //     </DialogContentText>
    //   }
    // />
  );
};

export default DeleteModal;
