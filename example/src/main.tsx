import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConvexProvider, ConvexReactClient } from "convex/react";
import { AuthzProvider } from "@djpanda/convex-authz/react";
import { api } from "@convex/_generated/api";
import App from "./App.jsx";
import "./index.css";

const address = import.meta.env.VITE_CONVEX_URL;

const convex = new ConvexReactClient(address);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexProvider client={convex}>
      <AuthzProvider
        queryRefs={{
          checkPermission: api.app.checkPermissionScoped,
          getUserRoles: api.app.getRoles,
        }}
      >
        <App />
      </AuthzProvider>
    </ConvexProvider>
  </StrictMode>,
);
