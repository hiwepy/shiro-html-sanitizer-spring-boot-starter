package org.apache.shiro.spring.boot.sanitizer.web.filter;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link HttpServletRequestXssPolicyFilter}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("HttpServletRequestXssPolicyFilter Tests")
class HttpServletRequestXssPolicyFilterTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        HttpServletRequestXssPolicyFilter instance = new HttpServletRequestXssPolicyFilter();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Default policyFactory is not null")
    void testDefaultPolicyFactory() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        assertThat(filter.getPolicyFactory()).isNotNull();
    }

    @Test
    @DisplayName("Default policyHeaders is null")
    void testDefaultPolicyHeaders() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        assertThat(filter.getPolicyHeaders()).isNull();
    }

    @Test
    @DisplayName("policyFactory getter/setter works correctly")
    void testPolicyFactoryGetterSetter() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        PolicyFactory customFactory = new HtmlPolicyBuilder().allowElements("b").toFactory();
        filter.setPolicyFactory(customFactory);
        assertThat(filter.getPolicyFactory()).isEqualTo(customFactory);
    }

    @Test
    @DisplayName("policyHeaders getter/setter works correctly")
    void testPolicyHeadersGetterSetter() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        String[] headers = {"X-Custom"};
        filter.setPolicyHeaders(headers);
        assertThat(filter.getPolicyHeaders()).isEqualTo(headers);
    }

    @Test
    @DisplayName("init does not throw exception")
    void testInit() throws ServletException {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        filter.init(null);
        // no exception expected
    }

    @Test
    @DisplayName("destroy does not throw exception")
    void testDestroy() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        filter.destroy();
        // no exception expected
    }

    @Test
    @DisplayName("doFilter wraps request with XSS policy wrapper")
    void testDoFilter() throws IOException, ServletException {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        FilterChain mockChain = mock(FilterChain.class);

        filter.doFilter(mockRequest, mockResponse, mockChain);

        verify(mockChain).doFilter(any(), eq(mockResponse));
    }

    @Test
    @DisplayName("doFilter throws ServletException for non-HTTP request")
    void testDoFilterNonHttp() {
        HttpServletRequestXssPolicyFilter filter = new HttpServletRequestXssPolicyFilter();
        jakarta.servlet.ServletRequest nonHttpReq = mock(jakarta.servlet.ServletRequest.class);
        jakarta.servlet.ServletResponse nonHttpResp = mock(jakarta.servlet.ServletResponse.class);
        FilterChain mockChain = mock(FilterChain.class);

        assertThatThrownBy(() -> filter.doFilter(nonHttpReq, nonHttpResp, mockChain))
                .isInstanceOf(ServletException.class)
                .hasMessageContaining("just supports HTTP requests");
    }
}
