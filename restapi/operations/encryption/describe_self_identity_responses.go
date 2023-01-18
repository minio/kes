// Code generated by go-swagger; DO NOT EDIT.

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
//

package encryption

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/minio/kes/models"
)

// DescribeSelfIdentityOKCode is the HTTP code returned for type DescribeSelfIdentityOK
const DescribeSelfIdentityOKCode int = 200

/*
DescribeSelfIdentityOK A successful response.

swagger:response describeSelfIdentityOK
*/
type DescribeSelfIdentityOK struct {

	/*
	  In: Body
	*/
	Payload *models.EncryptionDescribeSelfIdentityResponse `json:"body,omitempty"`
}

// NewDescribeSelfIdentityOK creates DescribeSelfIdentityOK with default headers values
func NewDescribeSelfIdentityOK() *DescribeSelfIdentityOK {

	return &DescribeSelfIdentityOK{}
}

// WithPayload adds the payload to the describe self identity o k response
func (o *DescribeSelfIdentityOK) WithPayload(payload *models.EncryptionDescribeSelfIdentityResponse) *DescribeSelfIdentityOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the describe self identity o k response
func (o *DescribeSelfIdentityOK) SetPayload(payload *models.EncryptionDescribeSelfIdentityResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DescribeSelfIdentityOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*
DescribeSelfIdentityDefault Generic error response.

swagger:response describeSelfIdentityDefault
*/
type DescribeSelfIdentityDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewDescribeSelfIdentityDefault creates DescribeSelfIdentityDefault with default headers values
func NewDescribeSelfIdentityDefault(code int) *DescribeSelfIdentityDefault {
	if code <= 0 {
		code = 500
	}

	return &DescribeSelfIdentityDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the describe self identity default response
func (o *DescribeSelfIdentityDefault) WithStatusCode(code int) *DescribeSelfIdentityDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the describe self identity default response
func (o *DescribeSelfIdentityDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the describe self identity default response
func (o *DescribeSelfIdentityDefault) WithPayload(payload *models.Error) *DescribeSelfIdentityDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the describe self identity default response
func (o *DescribeSelfIdentityDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DescribeSelfIdentityDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}