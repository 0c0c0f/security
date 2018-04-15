package com.corp.vul;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by 0c0c0f on 2015/12/8.
 */

public class SecurityHttpWrapper extends HttpServletRequestWrapper {
    public static boolean rx(String str, Pattern pattern) {
        Matcher matcher = pattern.matcher(str);
        boolean b = matcher.find();
        return b;
    }
    private static class SecurityRegex {
        static Pattern[] XSS_REG = null;
        static Pattern[] SQLI_REG = null;
        static Pattern[] RCE_REG = null;
        static Pattern[] whiteListURLs = null;
        static Pattern[] blackListURLs = null;
        static {
            String[] XSSREG = {};
            String[] SQLIREG = {};
            String[] RCEREG = { "xwork\\.MethodAccessor|java\\.lang" };
            String[] WLREG={};
            String[] BLREG={};

            XSS_REG = new Pattern[XSSREG.length];
            SQLI_REG = new Pattern[SQLIREG.length];
            RCE_REG = new Pattern[RCEREG.length];
            whiteListURLs = new Pattern[WLREG.length];
            blackListURLs = new Pattern[BLREG.length];
            for (int i = 0; i < XSSREG.length; i++) {
                XSS_REG[i] = Pattern.compile(XSSREG[i], Pattern.CASE_INSENSITIVE);
            }
            for (int i = 0; i < SQLIREG.length; i++) {
                SQLI_REG[i] = Pattern.compile(SQLIREG[i], Pattern.CASE_INSENSITIVE);
            }
            for (int i = 0; i < RCEREG.length; i++) {
                RCE_REG[i] = Pattern.compile(RCEREG[i], Pattern.CASE_INSENSITIVE);
            }
            for (int i = 0; i < WLREG.length; i++) {
                whiteListURLs[i] = Pattern.compile(WLREG[i], Pattern.CASE_INSENSITIVE);
            }
            for (int i = 0; i < BLREG.length; i++) {
                blackListURLs[i] = Pattern.compile(BLREG[i], Pattern.CASE_INSENSITIVE);
            }
        }
    }

    private HttpServletRequest orgRequest;
    public SecurityHttpWrapper(HttpServletRequest request) {
        super(request);
        orgRequest = request;
    }

    /**
     * 覆盖getParameter方法，将参数名和参数值都做xss过滤。
     * 如果需要获得原始的值，则通过super.getParameterValues(name)来获取
     * getParameterNames,getParameterValues和getParameterMap也可能需要覆盖
     */
    @Override
    public String getParameter(String name) {
        Boolean flag=false;
        String value = super.getParameter(name);
        String path = getRequestURI();
        //whitelist
        if(SecurityRegex.whiteListURLs.length != 0){
            for (int i = 0; i < SecurityRegex.whiteListURLs.length; i++) {
                flag = rx(path, SecurityRegex.whiteListURLs[i]);
                if (flag) {
                    return value;
                }
            }
        }
        //blacklist
        if(SecurityRegex.blackListURLs.length != 0){
            for (int i = 0; i < SecurityRegex.blackListURLs.length; i++) {
                flag = rx(path, SecurityRegex.blackListURLs[i]);
                if (flag) {
                    return "";
                }
            }
        }
        if (value != null) {
            // sqli filter
            for (int i = 0; i < SecurityRegex.SQLI_REG.length; i++) {
                flag = rx(value, SecurityRegex.SQLI_REG[i]);
                if (flag) {
                    System.out.print("alert");
                    return "";
                }
            }
            // xss filter
            for (int i = 0; i < SecurityRegex.XSS_REG.length; i++) {
                flag = rx(value, SecurityRegex.XSS_REG[i]);
                if (flag)
                    return SecurityUtil.SecurityXssScript(value);
            }
            // rec filter
            for (int i = 0; i < SecurityRegex.RCE_REG.length; i++) {
                flag = rx(value, SecurityRegex.RCE_REG[i]);
                if (flag) {
                    System.out.print("alert");
                    return "";
                }
            }
        }
        return value;
    }

    /**
     * 覆盖getHeader方法，将参数名和参数值都做xss过滤
     * 如果需要获得原始的值，则通过super.getHeaders(name)来获取getHeaderNames也可能需要覆盖
     */
    @Override
    public String getHeader(String name) {
        Boolean flag=false;
        String value = super.getHeader(name);
        String path = getRequestURI();
        //whitelist
        if(SecurityRegex.whiteListURLs.length != 0){
            for (int i = 0; i < SecurityRegex.whiteListURLs.length; i++) {
                flag = rx(path, SecurityRegex.whiteListURLs[i]);
                if (flag) {
                    return value;
                }
            }
        }
        //blacklist
        if(SecurityRegex.blackListURLs.length != 0){
            for (int i = 0; i < SecurityRegex.blackListURLs.length; i++) {
                flag = rx(path, SecurityRegex.blackListURLs[i]);
                if (flag) {
                    return "";
                }
            }
        }
        if (value != null) {
            // sqli filter
            for (int i = 0; i < SecurityRegex.SQLI_REG.length; i++) {
                flag = rx(value, SecurityRegex.SQLI_REG[i]);
                if (flag) {
                    System.out.print("alert");
                    return "";
                }
            }
            // xss filter
            for (int i = 0; i < SecurityRegex.XSS_REG.length; i++) {
                flag = rx(value, SecurityRegex.XSS_REG[i]);
                if (flag)
                    return SecurityUtil.SecurityXssScript(value);
            }
            // rec filter
            for (int i = 0; i < SecurityRegex.RCE_REG.length; i++) {
                flag = rx(value, SecurityRegex.RCE_REG[i]);
                if (flag) {
                    System.out.print("alert");
                    return "";
                }
            }
        }
        return value;
    }

    /**
     * 获取最原始的request
     *
     * @return
     */
    public HttpServletRequest getOrgRequest() {
        return orgRequest;
    }

    /**
     * 获取最原始的request的静态方法
     *
     * @return
     */
    public static HttpServletRequest getOrgRequest(HttpServletRequest req) {
        if (req instanceof SecurityHttpWrapper) {
            return ((SecurityHttpWrapper) req).getOrgRequest();
        }
        return req;
    }
}
