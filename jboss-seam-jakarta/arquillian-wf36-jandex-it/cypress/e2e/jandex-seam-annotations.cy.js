describe("Jandex Seam annotation matrix", () => {
  it("finds Name/Scope/Observer/In on PhaseOneAction", () => {
    cy.request("/probe?mode=matrix&target=phaseOneAction&annotations=Name,Scope,Observer,In").then((response) => {
      const body = (response.body || "").toString();
      expect(response.status).to.eq(200);
      expect(body).to.include("NAME=true");
      expect(body).to.include("SCOPE=true");
      expect(body).to.include("OBSERVER=true");
      expect(body).to.include("IN=true");
      expect(body).to.include("OVERALL=PASS");
    });
  });

  it("finds Name/Scope/Out/Observer on PhaseFourAction", () => {
    cy.request("/probe?mode=matrix&target=phaseFourAction&annotations=Name,Scope,Out,Observer").then((response) => {
      const body = (response.body || "").toString();
      expect(response.status).to.eq(200);
      expect(body).to.include("NAME=true");
      expect(body).to.include("SCOPE=true");
      expect(body).to.include("OUT=true");
      expect(body).to.include("OBSERVER=true");
      expect(body).to.include("OVERALL=PASS");
    });
  });

  it("reports missing seam annotations on PlainPojo", () => {
    cy.request("/probe?mode=matrix&target=missing&annotations=Name,Scope,Observer").then((response) => {
      const body = (response.body || "").toString();
      expect(response.status).to.eq(200);
      expect(body).to.include("NAME=false");
      expect(body).to.include("SCOPE=false");
      expect(body).to.include("OBSERVER=false");
      expect(body).to.include("OVERALL=FAIL");
    });
  });
});
