//  This file is part of MinIO KES
//  Copyright (c) 2022 MinIO, Inc.
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { IMenuItem } from "./menu/types";
import { NavLink } from "react-router-dom";
import { AuditLogsMenuIcon } from "mds";

export const ROUTES = {
  ENCRYPTION: "/encryption",
  ENCRYPTION_STATUS: "/encryption/status",
  ENCRYPTION_KEYS: "/encryption/keys",
  ENCRYPTION_KEYS_ADD: "/encryption/add-key/",
  ENCRYPTION_KEYS_IMPORT: "/encryption/import-key/",
  ENCRYPTION_POLICIES: "/encryption/policies",
  ENCRYPTION_POLICIES_ADD: "/encryption/add-policy",
  ENCRYPTION_POLICY_DETAILS: "/encryption/policies/:policyName",
  ENCRYPTION_IDENTITIES: "/encryption/identities",
};

export const validRoutes = () => {
  let consoleMenus: IMenuItem[] = [
    {
      group: "Encryption",
      name: "Status",
      id: "encryption-status",
      component: NavLink,
      icon: AuditLogsMenuIcon,
      to: ROUTES.ENCRYPTION_STATUS,
      children: [],
    },
    {
      group: "Encryption",
      name: "Keys",
      id: "encryption-keys",
      component: NavLink,
      icon: AuditLogsMenuIcon,
      to: ROUTES.ENCRYPTION_KEYS,
      children: [],
    },
    {
      group: "Encryption",
      name: "Policies",
      id: "encryption-policies",
      component: NavLink,
      icon: AuditLogsMenuIcon,
      to: ROUTES.ENCRYPTION_POLICIES,
      children: [],
    },
    {
      group: "Encryption",
      name: "Identities",
      id: "encryption-identities",
      component: NavLink,
      icon: AuditLogsMenuIcon,
      to: ROUTES.ENCRYPTION_IDENTITIES,
      children: [],
    },
  ];

  return consoleMenus;
};
