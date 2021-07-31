package com.example.securitytestapp.filter;

import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

@Component
public class HelloBasicAuthenticationFilter implements Filter {

    public static final String LOGIN = "user";
    public static final String PWD = "user1";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)servletRequest;
        HttpServletResponse resp = (HttpServletResponse)servletResponse;

        ///////////////
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            resp.getOutputStream().println("Please log in!");
            resp.getOutputStream().close();
            return; // чтобы цепочка фильтров не продолжалась
        }

        /////////////////
        String base64Credentials = authHeader.split(" ")[1];
        byte[] bytesDecodedCredentials = Base64.getDecoder().decode(base64Credentials);
        String credentials = new String(bytesDecodedCredentials);

        String login = credentials.split(":")[0];
        String password = credentials.split(":")[1];

        if (!LOGIN.equals(login) || !PWD.equals(password)) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getOutputStream().println("You can't see this content!");
            resp.getOutputStream().close();
            return;
        }

        /////////////////

        filterChain.doFilter(servletRequest,servletResponse);
    }
}
