//  This file is part of MinIO KES
//  Copyright (c) 2023 MinIO, Inc.
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
import {
  IdentitiesMenuIcon,
  KeysMenuIcon,
  PoliciesMenuIcon,
  SecretsMenuIcon,
  StatusMenuIcon,
} from "mds";

export const ROUTES = {
  ENCRYPTION: "/encryption",
  ENCRYPTION_STATUS: "/encryption/status",
  ENCRYPTION_METRICS: "/encryption/metrics",
  ENCRYPTION_VERSION: "/encryption/version",
  ENCRYPTION_SUPPORTED_ENDPOINTS: "/encryption/supported-endpoints",
  ENCRYPTION_KEYS: "/encryption/keys",
  ENCRYPTION_KEYS_ADD: "/encryption/add-key/",
  ENCRYPTION_KEYS_IMPORT: "/encryption/import-key/",
  ENCRYPTION_POLICIES: "/encryption/policies",
  ENCRYPTION_POLICIES_ADD: "/encryption/add-policy",
  ENCRYPTION_POLICY_DETAILS: "/encryption/policies/:policyName",
  ENCRYPTION_IDENTITIES: "/encryption/identities",
  ENCRYPTION_SECRETS: "/encryption/secrets",
  ENCRYPTION_SECRETS_ADD: "/encryption/add-secret/",
};

export const validRoutes = () => {
  let consoleMenus: IMenuItem[] = [
    {
      group: "Encryption",
      name: "Status",
      id: "encryption-status",
      icon: <StatusMenuIcon />,
      path: ROUTES.ENCRYPTION_STATUS,
    },
    {
      group: "Encryption",
      name: "Keys",
      id: "encryption-keys",
      icon: <KeysMenuIcon />,
      path: ROUTES.ENCRYPTION_KEYS,
    },
    {
      group: "Encryption",
      name: "Policies",
      id: "encryption-policies",
      icon: <PoliciesMenuIcon />,
      path: ROUTES.ENCRYPTION_POLICIES,
    },
    {
      group: "Encryption",
      name: "Identities",
      id: "encryption-identities",
      icon: <IdentitiesMenuIcon />,
      path: ROUTES.ENCRYPTION_IDENTITIES,
    },
    {
      group: "Encryption",
      name: "Secrets",
      id: "encryption-secret",
      icon: <SecretsMenuIcon />,
      path: ROUTES.ENCRYPTION_SECRETS,
    },
  ];

  return consoleMenus;
};
