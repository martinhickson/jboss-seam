describe("Jandex Seam probe", () => {
  it("returns FOUND from /probe", () => {
    cy.request("/probe").then((response) => {
      expect(response.status).to.eq(200);
      expect((response.body || "").trim()).to.eq("FOUND");
    });
  });
});
