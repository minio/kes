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

import React, {
    Fragment,
    useEffect,
    useState,
  } from "react";
  import { Theme } from "@mui/material/styles";
  import createStyles from "@mui/styles/createStyles";
  import withStyles from "@mui/styles/withStyles";
  import CssBaseline from "@mui/material/CssBaseline";
  import Snackbar from "@mui/material/Snackbar";
//   import { ErrorResponseHandler } from "../../common/types";
  import Menu from "./menu/Menu";
  
import { useAppDispatch, useAppSelector } from "../../app/hooks";
import { setSnackBarMessage } from "../../systemSlice";
    
  const styles = (theme: Theme) =>
    createStyles({
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
      // ...snackBarCommon,
    });
  
  interface IConsoleProps {
    classes: any;
  }
  
  const Console = ({ classes }: IConsoleProps) => {
    const dispatch = useAppDispatch();
    // const sidebarOpen = useAppSelector((state) => state.system.sidebarOpen);
    // const session = useAppSelector((state) => state.console.session);
    const snackBar = useAppSelector((state) => state.system.snackBar);
    // const snackBarMessage = useSelector(
    //   (state: AppState) => state.system.snackBar
    // );
    // const loadingProgress = useSelector(
    //   (state: AppState) => state.system.loadingProgress
    // );
  
    const [openSnackbar, setOpenSnackbar] = useState<boolean>(false);
  
  
    // // Layout effect to be executed after last re-render for resizing only
    // useLayoutEffect(() => {
    //   // Debounce to not execute constantly
    //   const debounceSize = debounce(() => {
    //     if (open && window.innerWidth <= 1024) {
    //       dispatch(menuOpen(false));
    //     }
    //   }, 300);
  
    //   // Added event listener for window resize
    //   window.addEventListener("resize", debounceSize);
  
    //   // We remove the listener on component unmount
    //   return () => window.removeEventListener("resize", debounceSize);
    // });
  
    // const consoleAdminRoutes: IRouteRule[] = [
    //   {
    //     component: ObjectBrowser,
    //     path: IAM_PAGES.OBJECT_BROWSER_VIEW,
    //     forceDisplay: true,
    //     customPermissionFnc: () => {
    //       const path = window.location.pathname;
    //       const resource = path.match(/browser\/(.*)\//);
    //       return (
    //         resource &&
    //         resource.length > 0 &&
    //         hasPermission(
    //           resource[1],
    //           IAM_PAGES_PERMISSIONS[IAM_PAGES.OBJECT_BROWSER_VIEW]
    //         )
    //       );
    //     },
    //   },
    //   {
    //     component: Buckets,
    //     path: IAM_PAGES.BUCKETS,
    //     forceDisplay: true,
    //   },
    //   {
    //     component: Dashboard,
    //     path: IAM_PAGES.DASHBOARD,
    //   },
    //   {
    //     component: Buckets,
    //     path: IAM_PAGES.ADD_BUCKETS,
    //     customPermissionFnc: () => {
    //       return hasPermission("*", IAM_PAGES_PERMISSIONS[IAM_PAGES.ADD_BUCKETS]);
    //     },
    //   },
    //   {
    //     component: Buckets,
    //     path: IAM_PAGES.BUCKETS_ADMIN_VIEW,
    //     customPermissionFnc: () => {
    //       const path = window.location.pathname;
    //       const resource = path.match(/buckets\/(.*)\/admin*/);
    //       return (
    //         resource &&
    //         resource.length > 0 &&
    //         hasPermission(
    //           resource[1],
    //           IAM_PAGES_PERMISSIONS[IAM_PAGES.BUCKETS_ADMIN_VIEW]
    //         )
    //       );
    //     },
    //   },
  
    //   {
    //     component: Watch,
    //     path: IAM_PAGES.TOOLS_WATCH,
    //   },
    //   {
    //     component: Speedtest,
    //     path: IAM_PAGES.TOOLS_SPEEDTEST,
    //   },
    //   {
    //     component: Users,
    //     path: IAM_PAGES.USERS,
    //     fsHidden: ldapIsEnabled,
    //     customPermissionFnc: () =>
    //       hasPermission(CONSOLE_UI_RESOURCE, [IAM_SCOPES.ADMIN_LIST_USERS]) ||
    //       hasPermission(S3_ALL_RESOURCES, [IAM_SCOPES.ADMIN_CREATE_USER]),
    //   },
    //   {
    //     component: Groups,
    //     path: IAM_PAGES.GROUPS,
    //     fsHidden: ldapIsEnabled,
    //   },
    //   {
    //     component: AddGroupScreen,
    //     path: IAM_PAGES.GROUPS_ADD,
    //   },
    //   {
    //     component: GroupsDetails,
    //     path: IAM_PAGES.GROUPS_VIEW,
    //   },
    //   {
    //     component: Policies,
    //     path: IAM_PAGES.POLICIES_VIEW,
    //   },
    //   {
    //     component: AddPolicyScreen,
    //     path: IAM_PAGES.POLICY_ADD,
    //   },
    //   {
    //     component: Policies,
    //     path: IAM_PAGES.POLICIES,
    //   },
    //   {
    //     component: IDPLDAPConfigurations,
    //     path: IAM_PAGES.IDP_LDAP_CONFIGURATIONS,
    //   },
    //   {
    //     component: IDPOpenIDConfigurations,
    //     path: IAM_PAGES.IDP_OPENID_CONFIGURATIONS,
    //   },
    //   {
    //     component: AddIDPLDAPConfiguration,
    //     path: IAM_PAGES.IDP_LDAP_CONFIGURATIONS_ADD,
    //   },
    //   {
    //     component: AddIDPOpenIDConfiguration,
    //     path: IAM_PAGES.IDP_OPENID_CONFIGURATIONS_ADD,
    //   },
    //   {
    //     component: IDPLDAPConfigurationDetails,
    //     path: IAM_PAGES.IDP_LDAP_CONFIGURATIONS_VIEW,
    //   },
    //   {
    //     component: IDPOpenIDConfigurationDetails,
    //     path: IAM_PAGES.IDP_OPENID_CONFIGURATIONS_VIEW,
    //   },
    //   {
    //     component: Heal,
    //     path: IAM_PAGES.TOOLS_HEAL,
    //   },
    //   {
    //     component: Trace,
    //     path: IAM_PAGES.TOOLS_TRACE,
    //   },
    //   {
    //     component: HealthInfo,
    //     path: IAM_PAGES.TOOLS_DIAGNOSTICS,
    //   },
    //   {
    //     component: ErrorLogs,
    //     path: IAM_PAGES.TOOLS_LOGS,
    //   },
    //   {
    //     component: LogsSearchMain,
    //     path: IAM_PAGES.TOOLS_AUDITLOGS,
    //   },
    //   {
    //     component: Health,
    //     path: IAM_PAGES.HEALTH,
    //   },
    //   {
    //     component: Tools,
    //     path: IAM_PAGES.TOOLS,
    //   },
    //   {
    //     component: ConfigurationOptions,
    //     path: IAM_PAGES.SETTINGS,
    //   },
    //   {
    //     component: AddNotificationEndpoint,
    //     path: IAM_PAGES.NOTIFICATIONS_ENDPOINTS_ADD_SERVICE,
    //   },
    //   {
    //     component: NotificationTypeSelector,
    //     path: IAM_PAGES.NOTIFICATIONS_ENDPOINTS_ADD,
    //   },
    //   {
    //     component: NotificationEndpoints,
    //     path: IAM_PAGES.NOTIFICATIONS_ENDPOINTS,
    //   },
    //   {
    //     component: AddTierConfiguration,
    //     path: IAM_PAGES.TIERS_ADD_SERVICE,
    //     fsHidden: !distributedSetup,
    //   },
    //   {
    //     component: TierTypeSelector,
    //     path: IAM_PAGES.TIERS_ADD,
    //     fsHidden: !distributedSetup,
    //   },
    //   {
    //     component: ListTiersConfiguration,
    //     path: IAM_PAGES.TIERS,
    //   },
    //   {
    //     component: SiteReplication,
    //     path: IAM_PAGES.SITE_REPLICATION,
    //   },
    //   {
    //     component: SiteReplicationStatus,
    //     path: IAM_PAGES.SITE_REPLICATION_STATUS,
    //   },
    //   {
    //     component: AddReplicationSites,
    //     path: IAM_PAGES.SITE_REPLICATION_ADD,
    //   },
    //   {
    //     component: Account,
    //     path: IAM_PAGES.ACCOUNT,
    //     forceDisplay: true,
    //     // user has implicit access to service-accounts
    //   },
    //   {
    //     component: AccountCreate,
    //     path: IAM_PAGES.ACCOUNT_ADD,
    //     forceDisplay: true, // user has implicit access to service-accounts
    //   },
    //   {
    //     component: License,
    //     path: IAM_PAGES.LICENSE,
    //     forceDisplay: true,
    //   },
    // ];
  
  
  
    // let routes = consoleAdminRoutes;
  
  
    // const allowedRoutes = routes.filter((route: any) =>
    //   route.forceDisplay && !route.fsHidden
    // );
  
    const closeSnackBar = () => {
      setOpenSnackbar(false);
      dispatch(setSnackBarMessage(""));
    };
  
    useEffect(() => {
      if (snackBar.message === "") {
        setOpenSnackbar(false);
        return;
      }
      // Open SnackBar
      if (snackBar.type !== "error") {
        setOpenSnackbar(true);
      }
    }, [snackBar]);
  
  
    return (
      <Fragment>
        {/* {session && session.status === "ok" ? ( */}
          <div className={classes.root}>
            <CssBaseline />
            <Menu />
  
            <main className={classes.content}>
              {/* {needsRestart && (
                <div className={classes.warningBar}>
                  {isServerLoading ? (
                    <Fragment>
                      The server is restarting.
                      <LinearProgress className={classes.progress} />
                    </Fragment>
                  ) : (
                    <Fragment>
                      The instance needs to be restarted for configuration changes
                      to take effect.{" "}
                      <Button
                        id={"restart-server"}
                        variant="secondary"
                        onClick={() => {
                          restartServer();
                        }}
                        label={"Restart"}
                      />
                    </Fragment>
                  )}
                </div>
              )} */}
              {/* {loadingProgress < 100 && (
                <LinearProgress
                  className={classes.progress}
                  variant="determinate"
                  value={loadingProgress}
                />
              )} */}
              {/* <MainError /> */}
              <div className={classes.snackDiv}>
                <Snackbar
                  open={openSnackbar}
                  onClose={() => {
                    closeSnackBar();
                  }}
                  autoHideDuration={
                    snackBar.type === "error" ? 10000 : 5000
                  }
                  message={snackBar.message}
                  className={classes.snackBarExternal}
                  ContentProps={{
                    className: `${classes.snackBar} ${
                      snackBar.type === "error"
                        ? classes.errorSnackBar
                        : ""
                    }`,
                  }}
                />
              </div>
              {/* <Suspense fallback={<LoadingComponent />}>
                <ObjectManager />
              </Suspense> */}
              {/* <Routes>
                {allowedRoutes.map((route: any) => (
                  <Route
                    key={route.path}
                    path={`${route.path}/*`}
                    element={
                      <Suspense fallback={<LoadingComponent />}>
                        <route.component {...route.props} />
                      </Suspense>
                    }
                  />
                ))}
                <Route
                  key={"icons"}
                  path={"icons"}
                  element={
                    <Suspense fallback={<LoadingComponent />}>
                      <IconsScreen />
                    </Suspense>
                  }
                />
                <Route
                  key={"components"}
                  path={"components"}
                  element={
                    <Suspense fallback={<LoadingComponent />}>
                      <ComponentsScreen />
                    </Suspense>
                  }
                />
                <Route
                  path={"*"}
                  element={
                    <Fragment>
                      {allowedRoutes.length > 0 ? (
                        <Navigate to={allowedRoutes[0].path} />
                      ) : (
                        <Fragment />
                      )}
                    </Fragment>
                  }
                />
              </Routes> */}
            </main>
          </div>
        {/* ) : null} */}
      </Fragment>
    );
  };
  
  export default withStyles(styles)(Console);
  