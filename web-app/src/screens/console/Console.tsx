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

import React, { Fragment, Suspense, useEffect, useState } from "react";
import { Theme } from "@mui/material/styles";
import Snackbar from "@mui/material/Snackbar";
import MenuWrapper from "./menu/MenuWrapper";

import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { setSnackBarMessage } from "../../systemSlice";
import { Route, Routes } from "react-router-dom";
import { ROUTES } from "./valid-routes";
import Status from "./encryption/api/Status";
import Version from "./encryption/api/Version";
import Metrics from "./encryption/api/Metrics";
import SupportedEndpoints from "./encryption/api/SupportedEndpoints";
import Keys from "./encryption/keys/Keys";
import AddKey from "./encryption/keys/AddKey";
import ImportKey from "./encryption/keys/ImportKey";
import Policies from "./encryption/policies/Policies";
import AddPolicy from "./encryption/policies/AddPolicy";
import PolicyDetails from "./encryption/policies/PolicyDetails";
import Identities from "./encryption/identities/Identities";
import Secrets from "./encryption/secrets/Secrets";
import AddSecret from "./encryption/secrets/AddSecret";
import makeStyles from "@mui/styles/makeStyles/makeStyles";
import { snackBarCommon } from "./common/styleLibrary";
import { MainContainer } from "mds";

const useStyles = makeStyles((theme: Theme) => ({
  root: {
    display: "flex",
    "& .MuiPaper-root.MuiSnackbarContent-root": {
      borderRadius: "0px 0px 5px 5px",
      boxShadow: "none",
    },
  },
  content: {
    flexGrow: 1,
    height: "100vh",
    overflow: "auto",
    position: "relative",
  },
  warningBar: {
    background: theme.palette.primary.main,
    color: "white",
    heigh: "60px",
    widht: "100%",
    lineHeight: "60px",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    "& button": {
      marginLeft: 8,
    },
  },
  progress: {
    height: "3px",
    backgroundColor: "#eaeaea",
  },
  ...snackBarCommon,
}));

const Console = () => {
  const dispatch = useAppDispatch();
  const classes = useStyles();
  const snackBar = useAppSelector((state) => state.system.snackBar);

  const [openSnackbar, setOpenSnackbar] = useState<boolean>(false);

  const consoleRoutes = [
    {
      component: Status,
      path: ROUTES.ENCRYPTION_STATUS,
    },
    {
      component: Version,
      path: ROUTES.ENCRYPTION_VERSION,
    },
    {
      component: Metrics,
      path: ROUTES.ENCRYPTION_METRICS,
    },
    {
      component: SupportedEndpoints,
      path: ROUTES.ENCRYPTION_SUPPORTED_ENDPOINTS,
    },
    {
      component: Keys,
      path: ROUTES.ENCRYPTION_KEYS,
    },
    {
      component: AddKey,
      path: ROUTES.ENCRYPTION_KEYS_ADD,
    },
    {
      component: ImportKey,
      path: ROUTES.ENCRYPTION_KEYS_IMPORT,
    },
    {
      component: Policies,
      path: ROUTES.ENCRYPTION_POLICIES,
    },
    {
      component: AddPolicy,
      path: ROUTES.ENCRYPTION_POLICIES_ADD,
    },
    {
      component: PolicyDetails,
      path: ROUTES.ENCRYPTION_POLICY_DETAILS,
    },
    {
      component: Identities,
      path: ROUTES.ENCRYPTION_IDENTITIES,
    },
    {
      component: Secrets,
      path: ROUTES.ENCRYPTION_SECRETS,
    },
    {
      component: AddSecret,
      path: ROUTES.ENCRYPTION_SECRETS_ADD,
    },
  ];

  const closeSnackBar = () => {
    setOpenSnackbar(false);
    dispatch(setSnackBarMessage(""));
  };

  useEffect(() => {
    if (snackBar.message === "") {
      setOpenSnackbar(false);
      return;
    }
    setOpenSnackbar(true);
  }, [snackBar]);

  return (
    <Fragment>
      <MainContainer menu={<MenuWrapper />}>
        <Fragment>
          <div className={classes.snackDiv}>
            <Snackbar
              open={openSnackbar}
              onClose={() => {
                closeSnackBar();
              }}
              autoHideDuration={5000}
              message={snackBar.message}
              className={classes.snackBarExternal}
              ContentProps={{
                className: `${classes.snackBar} ${
                  snackBar.type === "error" ? classes.errorSnackBar : ""
                }`,
              }}
            />
          </div>
          <Routes>
            {consoleRoutes.map((route: any) => (
              <Route
                key={route.path}
                path={`${route.path}/*`}
                element={
                  <Suspense>
                    <route.component />
                  </Suspense>
                }
              />
            ))}
          </Routes>
        </Fragment>
      </MainContainer>
    </Fragment>
  );
};

export default Console;
