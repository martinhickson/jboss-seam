describe("Jandex negative probe", () => {
  it("returns MISSING for non-annotated class", () => {
    cy.request("/probe?target=missing").then((response) => {
      expect(response.status).to.eq(200);
      expect((response.body || "").trim()).to.eq("MISSING");
    });
  });
});
