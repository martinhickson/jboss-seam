package org.jboss.seam.deployment;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.annotations.Name;

public class PageFlowServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();
        if (path == null || "/".equals(path) || "/start".equals(path)) {
            writeStartPage(resp);
            return;
        }
        if ("/step2".equals(path)) {
            writeStepTwoPage(resp);
            return;
        }
        resp.sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    private void writeStartPage(HttpServletResponse resp) throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        resp.getWriter().write(
                "<!doctype html><html><head><title>Flow Start</title></head><body>" +
                        "<h1>Flow Start</h1>" +
                        "<a data-testid='continue-link' href='step2'>Continue</a>" +
                        "</body></html>");
    }

    private void writeStepTwoPage(HttpServletResponse resp) throws IOException, ServletException {
        try {
            boolean found = hasNameAnnotation();
            resp.setContentType("text/html;charset=UTF-8");
            resp.getWriter().write(
                    "<!doctype html><html><head><title>Flow Step 2</title></head><body>" +
                            "<h1>Flow Step 2</h1>" +
                            "<div data-testid='scan-result'>Scan Result: " + (found ? "FOUND" : "MISSING") + "</div>" +
                            "</body></html>");
        } catch (Exception e) {
            throw new ServletException("Failed to evaluate Jandex scan in page flow", e);
        }
    }

    private boolean hasNameAnnotation() throws Exception {
        Set<Class<? extends Annotation>> annotations = new HashSet<Class<? extends Annotation>>();
        annotations.add(Name.class);
        return AbstractScanner.hasAnnotations(
                AbstractScanner.loadClassIndex(
                        "org/jboss/seam/jakarta/it/jandex/ScannedSeamComponent.class",
                        Thread.currentThread().getContextClassLoader()),
                annotations);
    }
}
