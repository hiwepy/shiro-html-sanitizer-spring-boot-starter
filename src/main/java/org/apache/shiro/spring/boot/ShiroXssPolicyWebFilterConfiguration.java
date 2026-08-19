package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.sanitizer.web.filter.HttpServletRequestXssPolicyFilter;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 默认拦截器
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@ConditionalOnWebApplication
@ConditionalOnClass({ org.owasp.html.PolicyFactory.class })
@ConditionalOnProperty(prefix = ShiroXssPolicyProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(ShiroXssPolicyProperties.class)
public class ShiroXssPolicyWebFilterConfiguration {

	/**
	 * policy Factory.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public PolicyFactory policyFactory() {
		return new HtmlPolicyBuilder().toFactory();
	}

	/**
	 * xss Policy Filter.
	 *
	 * @param policyFactory the policy factory
	 * @param properties the properties
	 * @return the result
	 */
	@Bean("xssPolicy")
	@ConditionalOnMissingBean(name = "xssPolicy")
	public FilterRegistrationBean<HttpServletRequestXssPolicyFilter> xssPolicyFilter(PolicyFactory policyFactory, ShiroXssPolicyProperties properties) {
		FilterRegistrationBean<HttpServletRequestXssPolicyFilter> registration = new FilterRegistrationBean<>();
		HttpServletRequestXssPolicyFilter xssPolicyFilter = new HttpServletRequestXssPolicyFilter();
		xssPolicyFilter.setPolicyFactory(policyFactory);
		xssPolicyFilter.setPolicyHeaders(properties.getPolicyHeaders());
		registration.setFilter(xssPolicyFilter);
		registration.setEnabled(false);
		return registration;
	}

}
