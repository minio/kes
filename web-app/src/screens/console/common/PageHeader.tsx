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
import { Theme } from "@mui/material/styles";
import createStyles from "@mui/styles/createStyles";
import withStyles from "@mui/styles/withStyles";

import { Box } from "@mui/material";
import { Grid } from "mds";

const styles = (theme: Theme) =>
  createStyles({
    headerContainer: {
      width: "100%",
      minHeight: 83,
      display: "flex",
      backgroundColor: "#fff",
      left: 0,
      borderBottom: "1px solid #E5E5E5",
    },
    label: {
      display: "flex",
      justifyContent: "flex-start",
      alignItems: "center",
    },
    rightMenu: {
      display: "flex",
      justifyContent: "flex-end",
      paddingRight: 20,
      "& button": {
        marginLeft: 8,
      },
    },
    logo: {
      marginLeft: 34,
      "& svg": {
        width: 150,
      },
    },
    middleComponent: {
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
    },
    indicator: {
      position: "absolute",
      display: "block",
      width: 15,
      height: 15,
      top: 0,
      right: 4,
      marginTop: 4,
      transitionDuration: "0.2s",
      color: "#32C787",
      "& svg": {
        width: 10,
        height: 10,
        top: "50%",
        left: "50%",
        transitionDuration: "0.2s",
      },
      "&.newItem": {
        color: "#2781B0",
        "& svg": {
          width: 15,
          height: 15,
        },
      },
    },
  });

interface IPageHeader {
  classes: any;
  label: any;
  actions?: any;
}

const PageHeader = ({
  classes,
  label,
  actions,
}: IPageHeader) => {

  return (
    <Grid
      container
      className={`${classes.headerContainer} page-header`}
      direction="row"
    >
      <Grid
        item
        xs={12}
        sm={12}
        md={6}
        className={classes.label}
        sx={{
          paddingTop:"15px",
          paddingRight: "15px",
          paddingLeft: "0",
          paddingBottom: "0",
        }}
      >
        <Box
          sx={{
            color: "#000",
            fontSize: 18,
            fontWeight: 700,
            marginLeft: "21px",
            display: "flex",
          }}
        >
          {label}
        </Box>
      </Grid>
      <Grid
        item
        xs={12}
        sm={12}
        md={6}
        className={classes.rightMenu}
      >
        {actions && actions}
      </Grid>
    </Grid>
  );
};

export default withStyles(styles)(PageHeader);
