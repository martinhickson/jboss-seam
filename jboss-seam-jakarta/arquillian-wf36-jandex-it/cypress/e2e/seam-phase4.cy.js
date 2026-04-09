describe("Seam phase4 outjection/interceptor probe", () => {
  it("verifies event-scoped outjection and observer dispatch", () => {
    cy.request("/phase4?signal=delta").then((response) => {
      const body = (response.body || "").toString();

      expect(response.status).to.eq(200);
      expect(body).to.include("SIGNAL=delta");
      expect(body).to.include("RESULT=dep-ok:delta");
      expect(body).to.include("OUTJECTION=out-delta");
      expect(body).to.include("OBSERVED=delta-event");
      expect(body).to.include("OVERALL=PASS");
    });
  });
});
