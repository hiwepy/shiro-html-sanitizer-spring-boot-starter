package org.apache.shiro.spring.boot.sanitizer.web.servlet.http;

import java.util.Enumeration;

import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PolicyEnumeration implements Enumeration<String> {

	private Logger LOG = LoggerFactory.getLogger(PolicyEnumeration.class);
	/**原始Header*/
	private Enumeration<String> headers;
	/**Xss检查策略工厂*/
	private PolicyFactory policy = null;
	
	public PolicyEnumeration( Enumeration<String> headers, PolicyFactory policy){
		this.headers = headers;
		this.policy = policy;
	}
	
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	@Override
	public String nextElement() {
		String taintedHeader = headers.nextElement();
		LOG.debug("Tainted Header :" + taintedHeader);
		String cleanHeader = policy.sanitize(taintedHeader);
		LOG.debug("XSS Clean Header :" + cleanHeader);
		return cleanHeader;
	}

}
