// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
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

// This object contains variables that will be used across form components.

export const actionsTray = {
  filterTitle: {
    color: "#848484",
    fontSize: 13,
    alignSelf: "center" as const,
    whiteSpace: "nowrap" as const,
    "&:not(:first-of-type)": {
      marginLeft: 10,
    },
  },
  label: {
    color: "#07193E",
    fontSize: 13,
    alignSelf: "center" as const,
    whiteSpace: "nowrap" as const,
    "&:not(:first-of-type)": {
      marginLeft: 10,
    },
  },
  timeContainers: {
    display: "flex" as const,
    "& button": {
      flexGrow: 0,
      marginLeft: 15,
    },
    height: 40,
    marginBottom: 15,
    justifyContent: "flex-start" as const,
    "& > *": {
      marginRight: 15,
    },
  },
  actionsTray: {
    display: "flex" as const,
    justifyContent: "space-between" as const,
    marginBottom: "1rem",
    alignItems: "center",
    "& button": {
      flexGrow: 0,
      marginLeft: 8,
    },
  },
  filterContainer: {
    backgroundColor: "#fff",
    border: "#EEF1F4 2px solid",
    borderRadius: 2,
    display: "flex",
    alignItems: "center",
    padding: "0 12px",
  },
  divisorLine: {
    borderRight: "#EEF1F4 1px solid",
    height: 20,
    margin: "0 15px",
  },
};

export const searchField = {
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
};

export const predefinedList = {
  prefinedContainer: {
    display: "flex",
    width: "100%",
    alignItems: "center" as const,
    margin: "15px 0 0",
  },
  predefinedTitle: {
    color: "rgba(0, 0, 0, 0.87)",
    display: "flex" as const,
    overflow: "hidden" as const,
    fontSize: 14,
    maxWidth: 160,
    textAlign: "left" as const,
    marginRight: 10,
    flexGrow: 0,
    fontWeight: "normal" as const,
  },
  predefinedList: {
    backgroundColor: "#fbfafa",
    border: "#e5e5e5 1px solid",
    padding: "12px 10px",
    color: "#696969",
    fontSize: 12,
    fontWeight: 600,
    minHeight: 41,
    borderRadius: 4,
  },
  innerContent: {
    width: "100%",
    overflowX: "auto" as const,
    whiteSpace: "nowrap" as const,
    scrollbarWidth: "none" as const,
    "&::-webkit-scrollbar": {
      display: "none",
    },
  },
  innerContentMultiline: {
    width: "100%",
    maxHeight: 100,
    overflowY: "auto" as const,
    scrollbarWidth: "none" as const,
    "&::-webkit-scrollbar": {
      display: "none",
    },
  },
  includesActionButton: {
    paddingRight: 45,
    position: "relative" as const,
  },
  overlayShareOption: {
    position: "absolute" as const,
    width: 45,
    right: 0,
    top: "50%",
    transform: "translate(0, -50%)",
  },
};

// ** According to W3 spec, default minimum values for flex width flex-grow is "auto" (https://drafts.csswg.org/css-flexbox/#min-size-auto). So in this case we need to enforce the use of an absolute width.
// "The preferred width of a box element child containing text content is currently the text without line breaks, leading to very unintuitive width and flex calculations → declare a width on a box element child with more than a few words (ever wonder why flexbox demos are all “1,2,3”?)"

export const snackBarCommon = {
  snackBar: {
    backgroundColor: "#081F44",
    fontWeight: 400,
    fontFamily: "Inter, sans-serif",
    fontSize: 14,
    boxShadow: "none" as const,
    "&.MuiPaper-root.MuiSnackbarContent-root": {
      borderRadius: "0px 0px 5px 5px",
    },
    "& div": {
      textAlign: "center" as const,
      padding: "6px 30px",
      width: "100%",
      overflowX: "hidden",
      textOverflow: "ellipsis",
    },
    "&.MuiPaper-root": {
      padding: "0px 20px 0px 20px",
    },
  },
  errorSnackBar: {
    backgroundColor: "#C72C48",
    color: "#fff",
  },
  snackBarExternal: {
    top: -1,
    height: 33,
    position: "fixed" as const,
    minWidth: 348,
    whiteSpace: "nowrap" as const,
    left: 0,
    width: "100%",
    justifyContent: "center" as const,
  },
  snackDiv: {
    top: "17px",
    left: "50%",
    position: "absolute" as const,
  },
  snackBarModal: {
    top: 0,
    position: "absolute" as const,
    minWidth: "348px",
    whiteSpace: "nowrap" as const,
    height: "33px",
    width: "100%",
    justifyContent: "center",
    left: 0,
  },
};

export const hrClass = {
  hrClass: {
    borderTop: 0,
    borderLeft: 0,
    borderRight: 0,
    borderColor: "#999999",
    backgroundColor: "transparent" as const,
  },
};

export const inlineCheckboxes = {
  inlineCheckboxes: {
    display: "flex",
    justifyContent: "flex-start",
  },
};