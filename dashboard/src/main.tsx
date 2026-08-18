import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./lib/theme"; // applies persisted theme to <html> before first paint
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
