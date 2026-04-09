const { defineConfig } = require("cypress");

module.exports = defineConfig({
  e2e: {
    baseUrl: process.env.CYPRESS_BASE_URL || "http://127.0.0.1:8080/jandex-scan-example",
    specPattern: "cypress/e2e/**/*.cy.js",
    supportFile: false
  },
  video: false
});
