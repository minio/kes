import React from "react";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Login from "./screens/login/Login";
import ConsoleApp from "./screens/console/ConsoleApp";
import ProtectedRoute from "./ProtectedRoute";
import Logout from "./screens/login/Logout";

const router = createBrowserRouter([
  {
    path: "/login",
    element: <Login />,
  },
  {
    path: "/logout",
    element: <Logout />,
  },
  {
    path: "/*",
    element: <ProtectedRoute Component={ConsoleApp} />,
  },
]);

const MainRouter = () => {
  return <RouterProvider router={router} />;
};

export default MainRouter;
