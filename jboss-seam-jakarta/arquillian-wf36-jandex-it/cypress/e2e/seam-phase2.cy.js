function parseProbeBody(body) {
  const text = (body || "").toString();
  return text.split("\n").reduce((acc, line) => {
    const idx = line.indexOf("=");
    if (idx > 0) {
      acc[line.substring(0, idx)] = line.substring(idx + 1);
    }
    return acc;
  }, {});
}

describe("Seam phase2 conversation probe", () => {
  it("propagates cid and retains conversation-scoped state", () => {
    cy.request("/phase2/start?signal=alpha").then((response) => {
      expect(response.status).to.eq(200);
      const start = parseProbeBody(response.body);

      expect(start.ACTION).to.eq("start");
      expect(start.OVERALL).to.eq("PASS");
      expect(start.LONG_RUNNING).to.eq("true");
      expect(start.LAST_SIGNAL).to.eq("alpha");
      expect(start.DEPENDENCY).to.eq("dep-ok");
      expect(start.CID).to.not.be.empty;
      expect(start.CID_PARAMETER).to.not.be.empty;

      const cid = encodeURIComponent(start.CID);
      const cidParameter = encodeURIComponent(start.CID_PARAMETER);
      const startCounter = Number(start.COUNTER);
      expect(Number.isNaN(startCounter)).to.eq(false);
      expect(startCounter).to.be.greaterThan(0);

      cy.request(`/phase2/step?${cidParameter}=${cid}&signal=beta`).then((step1Response) => {
        expect(step1Response.status).to.eq(200);
        const step1 = parseProbeBody(step1Response.body);

        expect(step1.ACTION).to.eq("step");
        expect(step1.OVERALL).to.eq("PASS");
        expect(step1.CID).to.eq(start.CID);
        expect(step1.LONG_RUNNING).to.eq("true");
        expect(Number(step1.COUNTER)).to.eq(startCounter + 1);
        expect(step1.LAST_SIGNAL).to.eq("beta");

        cy.request(`/phase2/end?${cidParameter}=${cid}&signal=omega`).then((endResponse) => {
          expect(endResponse.status).to.eq(200);
          const end = parseProbeBody(endResponse.body);

          expect(end.ACTION).to.eq("end");
          expect(end.OVERALL).to.eq("PASS");
          expect(end.CID).to.eq(start.CID);
          expect(end.ENDED).to.eq("true");
          expect(end.LONG_RUNNING).to.eq("false");
          expect(Number(end.COUNTER)).to.eq(startCounter + 2);
          expect(end.LAST_SIGNAL).to.eq("omega");
        });
      });
    });
  });
});
