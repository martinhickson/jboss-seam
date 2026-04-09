describe("JSF pages backed by Seam annotations", () => {
  it("navigates page1 to page2 and shows FOUND", () => {
    cy.visit("/pages/page1.xhtml");
    cy.get("[data-testid='jsf-page-one-title']").should("contain.text", "JSF Page One");
    cy.get("[data-testid='jsf-next-link']").click();
    cy.url().should("include", "/pages/page2.xhtml");
    cy.get("[data-testid='jsf-page-two-title']").should("contain.text", "JSF Page Two");
    cy.get("[data-testid='jsf-scan-result']").should("contain.text", "Scan Result: FOUND");
  });
});
