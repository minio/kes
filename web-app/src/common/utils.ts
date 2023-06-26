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

import storage from "local-storage-fallback";

export const deleteCookie = (name: string) => {
  document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:01 GMT;";
};

export const clearSession = () => {
  storage.removeItem("kes-ui-token");
  deleteCookie("kes-ui-token");
};
