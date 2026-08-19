package org.apache.shiro.spring.boot.sanitizer.web.filter;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.shiro.spring.boot.sanitizer.web.servlet.http.HttpServletXssPolicyRequestWrapper;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

/**
 * XSS(Cross Site Scripting)，即跨站脚本攻击请求过滤
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class HttpServletRequestXssPolicyFilter implements Filter {

	protected PolicyFactory DEFAULT_POLICY = new HtmlPolicyBuilder().toFactory();

	/**Xss检查策略工厂*/
	protected PolicyFactory policyFactory = DEFAULT_POLICY;
	/** 需要进行Xss检查的Header */
	protected String[] policyHeaders = null;

	/**
	 * init.
	 *
	 * @param filterConfig the filter config
	 * @throws ServletException if an error occurs
	 */
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// no-op
	}

	/**
	 * do Filter.
	 *
	 * @param request the request
	 * @param response the response
	 * @param filterChain the filter chain
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

		if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
			throw new ServletException("just supports HTTP requests");
		}

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		filterChain.doFilter(
				new HttpServletXssPolicyRequestWrapper(getPolicyFactory(), getPolicyHeaders(), httpRequest),
				httpResponse);
	}

	/**
	 * destroy.
	 *
	 */
	@Override
	public void destroy() {
		// no-op
	}

	/**
	 * Returns the policy factory.
	 *
	 * @return the policy factory
	 */
	public PolicyFactory getPolicyFactory() {
		return policyFactory;
	}

	/**
	 * Sets the policy factory.
	 *
	 * @param policyFactory the policy factory
	 */
	public void setPolicyFactory(PolicyFactory policyFactory) {
		this.policyFactory = policyFactory;
	}

	/**
	 * Returns the policy headers.
	 *
	 * @return the policy headers
	 */
	public String[] getPolicyHeaders() {
		return policyHeaders;
	}

	/**
	 * Sets the policy headers.
	 *
	 * @param policyHeaders the policy headers
	 */
	public void setPolicyHeaders(String[] policyHeaders) {
		this.policyHeaders = policyHeaders;
	}

}
