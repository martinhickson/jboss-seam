describe("Seam phase1 feature probe", () => {
  it("confirms context, bijection, events, and interceptors", () => {
    cy.request("/phase1").then((response) => {
      const body = (response.body || "").toString();
      expect(response.status).to.eq(200);
      expect(body).to.include("CONTEXT_EVENT=true");
      expect(body).to.include("CONTEXT_SESSION=true");
      expect(body).to.include("CONTEXT_CONVERSATION=true");
      expect(body).to.include("BIJECTION=dep-ok");
      expect(body).to.include("EVENT=event-ok");
      expect(body).to.include("INTERCEPTOR=true");
      expect(body).to.include("OVERALL=PASS");
    });
  });
});
