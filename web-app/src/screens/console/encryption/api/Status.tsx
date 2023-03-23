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

import React, { Fragment, useEffect, useState } from "react";
import { Box, Grid } from "@mui/material";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";

import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { TabPanel } from "../../common/TabPanel";
import {
  DisabledIcon,
  EnabledIcon,
  PageHeader,
  PageLayout,
  SectionTitle,
} from "mds";
import LabelValuePair from "../../common/LabelValuePair";
import LabelWithIcon from "../../common/LabelWithIcon";

import SupportedEndpoints from "./SupportedEndpoints";
import Metrics from "./Metrics";

const Status = () => {
  const dispatch = useAppDispatch();
  const [curTab, setCurTab] = useState<number>(0);

  const [status, setStatus] = useState<any | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);
  const [version, setVersion] = useState<any | null>(null);
  const [loadingVersion, setLoadingVersion] = useState<boolean>(true);

  // TODO: Use supported apis endpoint to check available apis
  const displayStatus = true;
  const displayVersion = true;

  useEffect(() => {
    setLoadingStatus(true);
  }, []);

  useEffect(() => {
    const loadVersion = () => {
      if (displayVersion) {
        api
          .invoke("GET", `/api/v1/encryption/version`)
          .then((result: any) => {
            if (result) {
              setVersion(result);
            }
            setLoadingVersion(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingVersion(false);
          });
      } else {
        setLoadingVersion(false);
      }
    };

    const loadStatus = () => {
      if (displayStatus) {
        api
          .invoke("GET", `/api/v1/encryption/status`)
          .then((result: any) => {
            if (result) {
              setStatus(result);
            }
            setLoadingStatus(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingStatus(false);
          });
      } else {
        setLoadingStatus(false);
      }
    };

    if (loadingStatus) {
      loadStatus();
    }
    if (loadingVersion) {
      loadVersion();
    }
  }, [dispatch, displayStatus, loadingStatus, displayVersion, loadingVersion]);

  const statusPanel = (
    <Fragment>
      <SectionTitle>Status</SectionTitle>
      <br />
      {status && (
        <Grid container spacing={1}>
          <Grid item xs={12}>
            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", sm: "2fr 1fr" },
                gridAutoFlow: { xs: "dense", sm: "row" },
                gap: 2,
              }}
            >
              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: { xs: "1fr", sm: "2fr 1fr" },
                  gridAutoFlow: { xs: "dense", sm: "row" },
                  gap: 2,
                }}
              >
                <LabelValuePair label={"Name:"} value={status.name} />
                {version && (
                  <LabelValuePair label={"Version:"} value={version.version} />
                )}
                <LabelValuePair
                  label={"Default Key ID:"}
                  value={status.defaultKeyID}
                />
                <LabelValuePair
                  label={"Key Management Service Endpoints:"}
                  value={
                    <Fragment>
                      {status.endpoints.map((e: any, i: number) => (
                        <LabelWithIcon
                          key={i}
                          icon={
                            e.status === "online" ? (
                              <EnabledIcon />
                            ) : (
                              <DisabledIcon />
                            )
                          }
                          label={e.url}
                        />
                      ))}
                    </Fragment>
                  }
                />
              </Box>
            </Box>
          </Grid>
        </Grid>
      )}
    </Fragment>
  );

  return (
    <Fragment>
      <PageHeader label="Status" />
      <PageLayout>
        <Tabs
          value={curTab}
          onChange={(e: React.ChangeEvent<{}>, newValue: number) => {
            setCurTab(newValue);
          }}
          indicatorColor="primary"
          textColor="primary"
          aria-label="cluster-tabs"
          variant="scrollable"
          scrollButtons="auto"
        >
          {/* <Tab
            label="Status"
            id="simple-tab-0"
            aria-controls="simple-tabpanel-0"
          /> */}
          <Tab
            label="Metrics"
            id="simple-tab-1"
            aria-controls="simple-tabpanel-1"
            onClick={() => {}}
          />
          <Tab
            label="APIs"
            id="simple-tab-2"
            aria-controls="simple-tabpanel-2"
          />
        </Tabs>

        {/* <TabPanel index={0} value={curTab}>
          <Box
            sx={{
              border: "1px solid #eaeaea",
              borderRadius: "2px",
              display: "flex",
              flexFlow: "column",
              padding: "43px",
            }}
          >
            {statusPanel}
          </Box>
        </TabPanel> */}
        <TabPanel index={0} value={curTab}>
          <Box
            sx={{
              border: "1px solid #eaeaea",
              borderRadius: "2px",
              display: "flex",
              flexFlow: "column",
              padding: "43px",
            }}
          >
            <Metrics />
          </Box>
        </TabPanel>
        <TabPanel index={1} value={curTab}>
          <Box
            sx={{
              border: "1px solid #eaeaea",
              borderRadius: "2px",
              display: "flex",
              flexFlow: "column",
              padding: "43px",
            }}
          >
            <SupportedEndpoints />
          </Box>
        </TabPanel>

        {false && (
          <TabPanel index={1} value={curTab}>
            <Box
              sx={{
                border: "1px solid #eaeaea",
                borderRadius: "2px",
                display: "flex",
                flexFlow: "column",
                padding: "43px",
              }}
            >
              {statusPanel}
            </Box>
          </TabPanel>
        )}
      </PageLayout>
    </Fragment>
  );
};

export default Status;
