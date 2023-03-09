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

import { LoginWrapper } from "mds";
import React, { Fragment } from "react";
import { useNavigate } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import LoginForm from "./LoginForm";
import { resetForm } from "./loginSlice";

const Login = () => {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const navigateTo = useAppSelector((state) => state.login.navigateTo);

  if (navigateTo !== "") {
    navigate(navigateTo);
    dispatch(resetForm());
  }

  return (
    <LoginWrapper
      promoHeader={<Fragment>KES</Fragment>}
      promoInfo={
        <Fragment>
          Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
          eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
          minim veniam, quis nostrud exercitation ullamco laboris nisi ut
          aliquip ex ea commodo consequat. Duis aute irure dolor in
          reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
          pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
          culpa qui officia deserunt mollit anim id est laborum.
        </Fragment>
      }
      logoProps={{
        applicationName: "kes",
      }}
      form={<LoginForm />}
      formFooter={
        <Fragment>
          Documentation│<a href={"/"}>GitHub</a>│Support│Download
        </Fragment>
      }
    />
  );
};

export default Login;
