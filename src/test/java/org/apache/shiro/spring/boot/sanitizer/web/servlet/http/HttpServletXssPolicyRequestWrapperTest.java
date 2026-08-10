package org.apache.shiro.spring.boot.sanitizer.web.servlet.http;

import java.util.Collections;
import java.util.Enumeration;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link HttpServletXssPolicyRequestWrapper}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("HttpServletXssPolicyRequestWrapper Tests")
class HttpServletXssPolicyRequestWrapperTest {

    private PolicyFactory policyFactory = new HtmlPolicyBuilder().toFactory();

    private HttpServletRequest createMockRequest() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameterMap()).thenReturn(Collections.emptyMap());
        return mockRequest;
    }

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        HttpServletRequest mockRequest = createMockRequest();
        HttpServletXssPolicyRequestWrapper instance = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("getParameter sanitizes XSS in parameter values")
    void testGetParameter() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getParameter("name")).thenReturn("<script>alert('xss')</script>value");
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        String result = wrapper.getParameter("name");
        assertThat(result).doesNotContain("<script>");
    }

    @Test
    @DisplayName("getParameter returns null when underlying returns null")
    void testGetParameterNull() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getParameter("name")).thenReturn(null);
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        assertThat(wrapper.getParameter("name")).isNull();
    }

    @Test
    @DisplayName("getParameterValues sanitizes XSS in parameter values")
    void testGetParameterValues() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getParameterValues("name")).thenReturn(new String[]{"<script>xss</script>", "safe"});
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        String[] result = wrapper.getParameterValues("name");
        assertThat(result).hasSize(2);
        assertThat(result[0]).doesNotContain("<script>");
        assertThat(result[1]).isEqualTo("safe");
    }

    @Test
    @DisplayName("getParameterValues returns null when underlying returns null")
    void testGetParameterValuesNull() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getParameterValues("name")).thenReturn(null);
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        assertThat(wrapper.getParameterValues("name")).isNull();
    }

    @Test
    @DisplayName("getParameterMap sanitizes XSS in parameter map values")
    void testGetParameterMap() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getParameterMap()).thenReturn(Collections.singletonMap("key", new String[]{"<b>bold</b>"}));
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        var result = wrapper.getParameterMap();
        assertThat(result).containsKey("key");
    }

    @Test
    @DisplayName("getHeader sanitizes XSS when header is in policy list")
    void testGetHeaderWithPolicy() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getHeader("X-Custom")).thenReturn("<script>xss</script>");
        String[] policyHeaders = {"X-Custom"};
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, policyHeaders, mockRequest);
        String result = wrapper.getHeader("X-Custom");
        assertThat(result).doesNotContain("<script>");
    }

    @Test
    @DisplayName("getHeader returns raw value when header is not in policy list")
    void testGetHeaderWithoutPolicy() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getHeader("X-Other")).thenReturn("raw-value");
        String[] policyHeaders = {"X-Custom"};
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, policyHeaders, mockRequest);
        String result = wrapper.getHeader("X-Other");
        assertThat(result).isEqualTo("raw-value");
    }

    @Test
    @DisplayName("getHeader returns null when underlying returns null")
    void testGetHeaderNull() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getHeader("X-Test")).thenReturn(null);
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        assertThat(wrapper.getHeader("X-Test")).isNull();
    }

    @Test
    @DisplayName("getHeaders returns PolicyEnumeration when header is in policy list")
    void testGetHeadersWithPolicy() {
        HttpServletRequest mockRequest = createMockRequest();
        Enumeration<String> headers = Collections.enumeration(Collections.singletonList("value"));
        when(mockRequest.getHeaders("X-Custom")).thenReturn(headers);
        String[] policyHeaders = {"X-Custom"};
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, policyHeaders, mockRequest);
        Enumeration<String> result = wrapper.getHeaders("X-Custom");
        assertThat(result).isInstanceOf(PolicyEnumeration.class);
    }

    @Test
    @DisplayName("getHeaders returns original enumeration when header is not in policy list")
    void testGetHeadersWithoutPolicy() {
        HttpServletRequest mockRequest = createMockRequest();
        Enumeration<String> headers = Collections.enumeration(Collections.singletonList("value"));
        when(mockRequest.getHeaders("X-Other")).thenReturn(headers);
        String[] policyHeaders = {"X-Custom"};
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, policyHeaders, mockRequest);
        Enumeration<String> result = wrapper.getHeaders("X-Other");
        assertThat(result).isSameAs(headers);
    }

    @Test
    @DisplayName("getCookies sanitizes XSS in cookie values")
    void testGetCookies() {
        HttpServletRequest mockRequest = createMockRequest();
        Cookie cookie = new Cookie("test", "<script>xss</script>");
        when(mockRequest.getCookies()).thenReturn(new Cookie[]{cookie});
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        Cookie[] result = wrapper.getCookies();
        assertThat(result).hasSize(1);
        assertThat(result[0].getValue()).doesNotContain("<script>");
    }

    @Test
    @DisplayName("getCookies returns null when underlying returns null")
    void testGetCookiesNull() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getCookies()).thenReturn(null);
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        assertThat(wrapper.getCookies()).isNull();
    }

    @Test
    @DisplayName("getQueryString sanitizes XSS in query string")
    void testGetQueryString() {
        HttpServletRequest mockRequest = createMockRequest();
        when(mockRequest.getQueryString()).thenReturn("<script>xss</script>");
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        String result = wrapper.getQueryString();
        assertThat(result).doesNotContain("<script>");
    }

    @Test
    @DisplayName("xssClean sanitizes HTML content")
    void testXssClean() {
        HttpServletRequest mockRequest = createMockRequest();
        HttpServletXssPolicyRequestWrapper wrapper = new HttpServletXssPolicyRequestWrapper(policyFactory, null, mockRequest);
        String result = wrapper.xssClean("<b>bold</b><script>evil</script>");
        assertThat(result).doesNotContain("<script>");
    }
}
