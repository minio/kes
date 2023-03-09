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

import { Box, Grid } from "@mui/material";
import { EnabledIcon } from "mds";
import React, { Fragment, useEffect, useState } from "react";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import LabelValuePair from "../../common/LabelValuePair";
import LabelWithIcon from "../../common/LabelWithIcon";
import SectionTitle from "../../common/SectionTitle";

const SupportedEndpoints = () => {
  const dispatch = useAppDispatch();
  const [apis, setAPIs] = useState<any | null>(null);
  const [loadingAPIs, setLoadingAPIs] = useState<boolean>(true);

  // TODO: Use supported apis endpoint to check available apis
  const displayAPIs = true;

  useEffect(() => {
    const loadAPIs = () => {
      if (displayAPIs) {
        api
          .invoke("GET", `/api/v1/encryption/apis`)
          .then((result: any) => {
            if (result) {
              setAPIs(result);
            }
            setLoadingAPIs(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingAPIs(false);
          });
      } else {
        setLoadingAPIs(false);
      }
    };

    if (loadingAPIs) {
      loadAPIs();
    }
  }, [dispatch, displayAPIs, loadingAPIs]);

  return (
    <Fragment>
      <SectionTitle>Supported API endpoints</SectionTitle>
      <br />
      {apis && (
        <Grid container spacing={1}>
          <Grid item xs={12}>
            <LabelValuePair
              label={""}
              value={
                <Box
                  sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "2fr 1fr" },
                    gridAutoFlow: { xs: "dense", sm: "row" },
                    gap: 2,
                  }}
                >
                  {apis.results.map((e: any, i: number) => (
                    <LabelWithIcon
                      key={i}
                      icon={<EnabledIcon />}
                      label={`${e.path} - ${e.method}`}
                    />
                  ))}
                </Box>
              }
            />
          </Grid>
        </Grid>
      )}
    </Fragment>
  );
};

export default SupportedEndpoints;
