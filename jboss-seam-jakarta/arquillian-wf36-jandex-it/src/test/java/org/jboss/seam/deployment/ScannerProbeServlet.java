package org.jboss.seam.deployment;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.jandex.Index;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Scope;

public class ScannerProbeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            String classResource = classResource(req.getParameter("target"));
            Index index = AbstractScanner.loadClassIndex(
                    classResource,
                    Thread.currentThread().getContextClassLoader());

            String annotationCsv = req.getParameter("annotations");
            if (annotationCsv == null || annotationCsv.trim().isEmpty()) {
                annotationCsv = "Name";
            }

            Map<String, Boolean> matrix = resolveAnnotationMatrix(index, annotationCsv);
            boolean found = matrix.containsValue(Boolean.TRUE);

            resp.setContentType("text/plain");
            if ("matrix".equals(req.getParameter("mode"))) {
                boolean allFound = true;
                for (Map.Entry<String, Boolean> entry : matrix.entrySet()) {
                    resp.getWriter().write(entry.getKey().toUpperCase() + "=" + entry.getValue() + "\n");
                    allFound = allFound && entry.getValue();
                }
                resp.getWriter().write("OVERALL=" + (allFound ? "PASS" : "FAIL") + "\n");
            } else {
                resp.getWriter().write(found ? "FOUND" : "MISSING");
            }
        } catch (Exception e) {
            throw new ServletException("Failed scanner probe", e);
        }
    }

    private static String classResource(String target) {
        if ("missing".equals(target)) {
            return "org/jboss/seam/jakarta/it/jandex/PlainPojo.class";
        }
        if ("phaseOneAction".equals(target)) {
            return "org/jboss/seam/jakarta/it/jandex/PhaseOneAction.class";
        }
        if ("phaseTwoConversationState".equals(target)) {
            return "org/jboss/seam/jakarta/it/jandex/PhaseTwoConversationState.class";
        }
        if ("phaseFourAction".equals(target)) {
            return "org/jboss/seam/jakarta/it/jandex/PhaseFourAction.class";
        }
        return "org/jboss/seam/jakarta/it/jandex/ScannedSeamComponent.class";
    }

    private static Map<String, Boolean> resolveAnnotationMatrix(Index index, String csv) {
        Map<String, Boolean> matrix = new LinkedHashMap<String, Boolean>();
        for (String token : csv.split(",")) {
            String key = token == null ? "" : token.trim();
            if (key.isEmpty()) {
                continue;
            }
            Set<Class<? extends Annotation>> set = new HashSet<Class<? extends Annotation>>();
            set.add(annotationByName(key));
            matrix.put(key, AbstractScanner.hasAnnotations(index, set));
        }
        return matrix;
    }

    private static Class<? extends Annotation> annotationByName(String name) {
        if ("Name".equals(name)) {
            return Name.class;
        }
        if ("Scope".equals(name)) {
            return Scope.class;
        }
        if ("Observer".equals(name)) {
            return Observer.class;
        }
        if ("In".equals(name)) {
            return In.class;
        }
        if ("Out".equals(name)) {
            return Out.class;
        }
        throw new IllegalArgumentException("Unsupported annotation token: " + name);
    }
}
