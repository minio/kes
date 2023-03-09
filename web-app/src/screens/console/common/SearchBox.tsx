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
import InputAdornment from "@mui/material/InputAdornment";
import { SearchIcon } from "mds";
import TextField from "@mui/material/TextField";
import withStyles from "@mui/styles/withStyles";
import { Theme } from "@mui/material/styles";
import createStyles from "@mui/styles/createStyles";

const styles = (theme: Theme) =>
  createStyles({
    searchField: {
      flexGrow: 1,
      height: 38,
      background: "#FFFFFF",
      borderRadius: 3,
      border: "#EAEDEE 1px solid",
      display: "flex",
      justifyContent: "center",
      padding: "0 16px",
      "& label, & label.MuiInputLabel-shrink": {
        fontSize: 10,
        transform: "translate(5px, 2px)",
        transformOrigin: "top left",
      },
      "& input": {
        fontSize: 12,
        fontWeight: 700,
        color: "#000",
        "&::placeholder": {
          color: "#858585",
          opacity: 1,
          fontWeight: 400,
        },
      },
      "&:hover": {
        borderColor: "#000",
      },
      "& .min-icon": {
        width: 16,
        height: 16,
      },
      "&:focus-within": {
        borderColor: "rgba(0, 0, 0, 0.87)",
      },
    },
  });

type SearchBoxProps = {
  placeholder?: string;
  value: string;
  classes: any;
  onChange: (value: string) => void;
  adornmentPosition?: "start" | "end";
  overrideClass?: any;
};

const SearchBox = ({
  placeholder = "",
  classes,
  onChange,
  adornmentPosition = "end",
  overrideClass,
  value,
}: SearchBoxProps) => {
  const inputProps = {
    disableUnderline: true,
    [`${adornmentPosition}Adornment`]: (
      <InputAdornment position={adornmentPosition}>
        <SearchIcon />
      </InputAdornment>
    ),
  };
  return (
    <TextField
      placeholder={placeholder}
      className={overrideClass ? overrideClass : classes.searchField}
      id="search-resource"
      label=""
      InputProps={inputProps}
      onChange={(e) => {
        onChange(e.target.value);
      }}
      variant="standard"
      value={value}
    />
  );
};

export default withStyles(styles)(SearchBox);
