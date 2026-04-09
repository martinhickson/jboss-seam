function parseBodyMap(body) {
  return (body || "").toString().split("\n").reduce((acc, line) => {
    const idx = line.indexOf("=");
    if (idx > 0) {
      acc[line.substring(0, idx)] = line.substring(idx + 1);
    }
    return acc;
  }, {});
}

describe("Seam phase3 session/application probe", () => {
  it("keeps session state and raises phase3 signal", () => {
    cy.request("/phase3?signal=s1").then((firstResponse) => {
      expect(firstResponse.status).to.eq(200);
      const first = parseBodyMap(firstResponse.body);

      expect(first.OVERALL).to.eq("PASS");
      expect(first.DEPENDENCY).to.eq("dep-ok");
      expect(first.LAST_SIGNAL).to.eq("s1");

      const firstSessionHits = Number(first.SESSION_HITS);
      const firstApplicationHits = Number(first.APPLICATION_HITS);
      expect(Number.isNaN(firstSessionHits)).to.eq(false);
      expect(Number.isNaN(firstApplicationHits)).to.eq(false);
      expect(firstSessionHits).to.be.greaterThan(0);
      expect(firstApplicationHits).to.be.greaterThan(0);

      cy.request("/phase3?signal=s2").then((secondResponse) => {
        expect(secondResponse.status).to.eq(200);
        const second = parseBodyMap(secondResponse.body);

        expect(second.OVERALL).to.eq("PASS");
        expect(second.DEPENDENCY).to.eq("dep-ok");
        expect(second.LAST_SIGNAL).to.eq("s2");
        expect(Number(second.SESSION_HITS)).to.eq(firstSessionHits + 1);
        expect(Number(second.APPLICATION_HITS)).to.be.gte(firstApplicationHits + 1);
      });
    });
  });
});
