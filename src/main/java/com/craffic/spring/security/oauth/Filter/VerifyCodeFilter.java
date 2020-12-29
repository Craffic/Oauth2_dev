package com.craffic.spring.security.oauth.Filter;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class VerifyCodeFilter extends GenericFilterBean {
    private String defaultFilterProcessUrl = "/doLogin";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        if ("POST".equalsIgnoreCase(httpServletRequest.getMethod()) && defaultFilterProcessUrl.equalsIgnoreCase(httpServletRequest.getServletPath())){
            // 验证码验证
            String code = httpServletRequest.getParameter("code");
            String verifyCode = (String)httpServletRequest.getSession().getAttribute("verify_code");
            if (StringUtils.isEmpty(code)){
                throw new AuthenticationServiceException("验证码不能为空!");
            }
            if (!verifyCode.toLowerCase().equals(code.toLowerCase())){
                throw new AuthenticationServiceException("验证码错误!");
            }
        }
        filterChain.doFilter(request, response);
    }
}
