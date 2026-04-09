package org.jboss.seam.deployment;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.jandex.Index;
import org.jboss.seam.annotations.Name;

public class ScannerProbeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            String classResource = "org/jboss/seam/jakarta/it/jandex/ScannedSeamComponent.class";
            if ("missing".equals(req.getParameter("target"))) {
                classResource = "org/jboss/seam/jakarta/it/jandex/PlainPojo.class";
            }
            Index index = AbstractScanner.loadClassIndex(
                    classResource,
                    Thread.currentThread().getContextClassLoader());
            Set<Class<? extends Annotation>> annotations = new HashSet<Class<? extends Annotation>>();
            annotations.add(Name.class);
            boolean found = AbstractScanner.hasAnnotations(index, annotations);
            resp.setContentType("text/plain");
            resp.getWriter().write(found ? "FOUND" : "MISSING");
        } catch (Exception e) {
            throw new ServletException("Failed scanner probe", e);
        }
    }
}
