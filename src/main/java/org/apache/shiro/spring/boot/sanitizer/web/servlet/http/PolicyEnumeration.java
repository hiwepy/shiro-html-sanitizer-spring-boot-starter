package org.apache.shiro.spring.boot.sanitizer.web.servlet.http;

import java.util.Enumeration;

import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>Policy Enumeration.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class PolicyEnumeration implements Enumeration<String> {

	private Logger LOG = LoggerFactory.getLogger(PolicyEnumeration.class);
	/**原始Header*/
	private Enumeration<String> headers;
	/**Xss检查策略工厂*/
	private PolicyFactory policy = null;
	
	/**
	 * Constructs a new policy enumeration instance.
	 *
	 * @param headers the headers
	 * @param policy the policy
	 */
	public PolicyEnumeration( Enumeration<String> headers, PolicyFactory policy){
		this.headers = headers;
		this.policy = policy;
	}
	
	/**
	 * Determines whether has more elements.
	 *
	 * @return the result
	 */
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	/**
	 * next Element.
	 *
	 * @return the result
	 */
	@Override
	public String nextElement() {
		String taintedHeader = headers.nextElement();
		LOG.debug("Tainted Header :" + taintedHeader);
		String cleanHeader = policy.sanitize(taintedHeader);
		LOG.debug("XSS Clean Header :" + cleanHeader);
		return cleanHeader;
	}

}
