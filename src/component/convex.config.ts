import { defineComponent } from "convex/server";
import crons from "@convex-dev/crons/convex.config.js";

const component = defineComponent("authz");
// Only register crons child when running in Convex runtime (has componentDefinitionPath); skip in Vitest
const cronsConfig = crons as { componentDefinitionPath?: string };
if (typeof cronsConfig.componentDefinitionPath === "string") {
  component.use(crons, { name: "crons" });
}
export default component;
