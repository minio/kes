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

import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";

import { userLogged } from "../../systemSlice";

import { useAppDispatch } from "../../app/hooks";
import { resetSession } from "../console/consoleSlice";
import api from "../../common/api";
import { ErrorResponseHandler } from "../../common/api/types";

const deleteCookie = (name: string) => {
  document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:01 GMT;";
};

const clearSession = () => {
  deleteCookie("kes-ui-token");
  localStorage.setItem("userLoggedIn", "");
};

const Logout = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  useEffect(() => {
    const logout = () => {
      const deleteSession = () => {
        clearSession();
        dispatch(userLogged(false));
        dispatch(resetSession());
        navigate(`/login`);
      };
      api
        .invoke("POST", `/api/v1/logout`)
        .then(() => {
          deleteSession();
        })
        .catch((err: ErrorResponseHandler) => {
          deleteSession();
        });
    };
    logout();
  }, [dispatch, navigate]);
  return <></>;
};

export default Logout;
