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

package restapi

import (
	"github.com/minio/kes/models"
)

type APIError struct {
	Code            int32
	Message         string
	DetailedMessage string
}

var (
	ErrForbidden     = &APIError{Code: 403, Message: "Forbidden", DetailedMessage: "You are not authorized to perform this operation"}
	ErrBadRequest    = &APIError{Code: 400, Message: "Bad Request", DetailedMessage: "The request is invalid"}
	ErrNotFound      = &APIError{Code: 404, Message: "Not Found", DetailedMessage: "The requested resource was not found"}
	ErrInternalError = &APIError{Code: 500, Message: "Internal Server Error", DetailedMessage: "An internal server error occurred"}
)

func newAPIError(code int32, message string, detailedMessage string) *models.Error {
	return &models.Error{
		Code:            code,
		Message:         &message,
		DetailedMessage: &detailedMessage,
	}
}

func newDefaultAPIError(err error) *models.Error {
	msg := err.Error()
	return &models.Error{
		Code:            500,
		Message:         &msg,
		DetailedMessage: &msg,
	}
}

func getAPIError(err *APIError) *models.Error {
	return &models.Error{
		Code:            err.Code,
		Message:         &err.Message,
		DetailedMessage: &err.DetailedMessage,
	}
}
