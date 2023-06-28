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
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useAppDispatch } from "../../../../app/hooks";
import api from "../../../../common/api";
import { ErrorResponseHandler } from "../../../../common/api/types";
import { setErrorSnackMessage } from "../../../../systemSlice";
import { PageHeader, PageLayout } from "mds";

const Metrics = () => {
  const dispatch = useAppDispatch();
  const [metrics, setMetrics] = useState<any | null>(null);
  const [loadingMetrics, setLoadingMetrics] = useState<boolean>(true);

  // TODO: Use supported apis endpoint to check available apis
  const displayMetrics = true;

  useEffect(() => {
    const loadMetrics = () => {
      if (displayMetrics) {
        api
          .invoke("GET", `/api/v1/encryption/metrics`)
          .then((result: any) => {
            if (result) {
              setMetrics(result);
            }
            setLoadingMetrics(false);
          })
          .catch((err: ErrorResponseHandler) => {
            dispatch(setErrorSnackMessage(err));
            setLoadingMetrics(false);
          });
      } else {
        setLoadingMetrics(false);
      }
    };

    if (loadingMetrics) {
      loadMetrics();
    }
  }, [dispatch, displayMetrics, loadingMetrics]);

  const getAPIRequestsData = () => {
    return [
      { label: "Success", success: metrics.requestOK },
      { label: "Failures", failures: metrics.requestFail },
      { label: "Errors", errors: metrics.requestErr },
      { label: "Active", active: metrics.requestActive },
    ];
  };

  const getEventsData = () => {
    return [
      { label: "Audit", audit: metrics.auditEvents },
      { label: "Errors", errors: metrics.errorEvents },
    ];
  };

  const getHistogramData = () => {
    return metrics.latencyHistogram.map((h: any) => {
      return {
        ...h,
        duration: `${h.duration / 1000000}ms`,
      };
    });
  };

  return (
    metrics && (
      <Fragment>
        <PageHeader label="Metrics" />
        <PageLayout>
          <h3>API Requests</h3>
          <BarChart width={750} height={250} data={getAPIRequestsData()}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="success" fill="green" />
            <Bar dataKey="failures" fill="red" />
            <Bar dataKey="errors" fill="black" />
            <Bar dataKey="active" fill="#8884d8" />
          </BarChart>
          <h3>Events</h3>
          <BarChart width={750} height={250} data={getEventsData()}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="label" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Bar dataKey="audit" fill="green" />
            <Bar dataKey="errors" fill="black" />
          </BarChart>
          <h3>Latency Histogram</h3>
          {metrics.latencyHistogram && (
            <LineChart
              width={730}
              height={250}
              data={getHistogramData()}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="duration" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="total"
                stroke="#8884d8"
                name={"Requests that took T ms or less"}
              />
            </LineChart>
          )}
        </PageLayout>
      </Fragment>
    )
  );
};

export default Metrics;
