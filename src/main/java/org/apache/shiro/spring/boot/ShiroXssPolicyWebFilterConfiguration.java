package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.sanitizer.web.filter.HttpServletRequestXssPolicyFilter;
import org.apache.shiro.spring.web.config.AbstractShiroWebFilterConfiguration;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
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
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration" // shiro-spring-boot-web-starter
})
@ConditionalOnWebApplication
@ConditionalOnClass({ org.owasp.html.PolicyFactory.class })
@ConditionalOnProperty(prefix = ShiroXssPolicyProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(ShiroXssPolicyProperties.class)
public class ShiroXssPolicyWebFilterConfiguration extends AbstractShiroWebFilterConfiguration {
	 
	@Bean
	@ConditionalOnMissingBean
	public PolicyFactory policyFactory() {
		return new HtmlPolicyBuilder().toFactory();
	}
	
	@Bean("xssPolicy")
	@ConditionalOnMissingBean(name = "xssPolicy")
	public FilterRegistrationBean<HttpServletRequestXssPolicyFilter> xssPolicyFilter(PolicyFactory policyFactory, ShiroXssPolicyProperties properties){
		FilterRegistrationBean<HttpServletRequestXssPolicyFilter> registration = new FilterRegistrationBean<HttpServletRequestXssPolicyFilter>();
		HttpServletRequestXssPolicyFilter xssPolicyFilter = new HttpServletRequestXssPolicyFilter();
		xssPolicyFilter.setPolicyFactory(policyFactory);
		xssPolicyFilter.setPolicyHeaders(properties.getPolicyHeaders());
		registration.setFilter(xssPolicyFilter);
	    registration.setEnabled(false); 
	    return registration;
	}

}
