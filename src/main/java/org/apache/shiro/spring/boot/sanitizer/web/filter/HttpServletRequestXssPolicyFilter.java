package org.apache.shiro.spring.boot.sanitizer.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.spring.boot.sanitizer.web.servlet.http.HttpServletXssPolicyRequestWrapper;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

/**
 * XSS(Cross Site Scripting)，即跨站脚本攻击请求过滤
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestXssPolicyFilter extends AccessControlFilter {
	
	protected PolicyFactory DEFAULT_POLICY = new HtmlPolicyBuilder().toFactory();
	
	/**Xss检查策略工厂*/
	protected PolicyFactory policyFactory = DEFAULT_POLICY;
	/** 需要进行Xss检查的Header */
	protected String[] policyHeaders = null;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return true;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}
	
	@Override
	public void executeChain(ServletRequest request,
			ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		
		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException( "just supports HTTP requests");
		}
		
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		
		filterChain.doFilter(new HttpServletXssPolicyRequestWrapper(getPolicyFactory(), getPolicyHeaders(), httpRequest), httpResponse);
		
	}

	public PolicyFactory getPolicyFactory() {
		return policyFactory;
	}

	public void setPolicyFactory(PolicyFactory policyFactory) {
		this.policyFactory = policyFactory;
	}

	public String[] getPolicyHeaders() {
		return policyHeaders;
	}

	public void setPolicyHeaders(String[] policyHeaders) {
		this.policyHeaders = policyHeaders;
	}
 
	
}
