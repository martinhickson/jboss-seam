describe("Seam page flow with Jandex scan", () => {
  it("navigates start to step2 and shows FOUND", () => {
    cy.visit("/flow/start");
    cy.get("[data-testid='continue-link']").click();
    cy.url().should("include", "/flow/step2");
    cy.get("[data-testid='scan-result']").should("contain.text", "Scan Result: FOUND");
  });
});
