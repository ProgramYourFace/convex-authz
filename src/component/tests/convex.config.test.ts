import { describe, expect, it } from "vitest";
import component from "../convex.config.js";

describe("convex.config", () => {
  it("should export a component definition", () => {
    expect(component).toBeDefined();
  });
});
