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

import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import api from "./common/api";
import { ISessionResponse } from "./screens/console/types";
import { userLogged } from "./systemSlice";
import { saveSessionResponse } from "./screens/console/consoleSlice";
import { useAppDispatch, useAppSelector } from "./app/hooks";
import LoadingComponent from "./common/LoadingComponent";

interface ProtectedRouteProps {
  Component: any;
}

const ProtectedRoute = ({ Component }: ProtectedRouteProps) => {
  const dispatch = useAppDispatch();

  const [sessionLoading, setSessionLoading] = useState<boolean>(true);
  const userLoggedIn = useAppSelector((state) => state.system.loggedIn);

  useEffect(() => {
    api
      .invoke("GET", `/api/v1/session`)
      .then((res: ISessionResponse) => {
        dispatch(saveSessionResponse(res));
        dispatch(userLogged(true));
        setSessionLoading(false);
      })
      .catch(() => {
        setSessionLoading(false);
        dispatch(userLogged(false));
      });
  }, [dispatch]);
  if (sessionLoading) {
    return <LoadingComponent />;
  }
  return userLoggedIn ? <Component /> : <Navigate to={{ pathname: `login` }} />;
};

export default ProtectedRoute;
