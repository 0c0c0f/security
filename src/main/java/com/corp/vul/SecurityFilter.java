package com.corp.vul;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Created by 0c0c0f on 2015/12/8.
 */

@WebFilter(filterName = "SecurityFilter")
public class SecurityFilter implements Filter {
    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException, IOException {
        SecurityHttpWrapper securityRequest = new SecurityHttpWrapper((HttpServletRequest) req);
        chain.doFilter(securityRequest, resp);
    }

    public void init(FilterConfig config) throws ServletException {
        System.out.println("Xss filter inited!");
    }
}
