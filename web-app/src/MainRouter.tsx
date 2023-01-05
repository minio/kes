import React from 'react';
import {createBrowserRouter, RouterProvider} from "react-router-dom";
import Login from "./screens/login/Login";
import App from "./App";

const router = createBrowserRouter([
    {
        path: "/login",
        element: <Login/>,
    },
    {
        path: "/",
        element: <App/>,
    },
]);

const MainRouter = () => {
    return <RouterProvider router={router}/>
}

export default MainRouter;