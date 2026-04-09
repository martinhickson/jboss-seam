package org.jboss.seam.jakarta.it.jandex;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.Component;

public class ProbeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Object component = Component.forName("jandexProbe");
        resp.setContentType("text/plain");
        resp.getWriter().write(component != null ? "FOUND" : "MISSING");
    }
}
