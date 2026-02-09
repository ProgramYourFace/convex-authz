import { describe, expect, it } from "vitest";
import { useMyComponent } from "./index.js";

describe("react hooks", () => {
  describe("useMyComponent", () => {
    it("should return an empty object", () => {
      const result = useMyComponent();
      expect(result).toEqual({});
    });
  });
});
