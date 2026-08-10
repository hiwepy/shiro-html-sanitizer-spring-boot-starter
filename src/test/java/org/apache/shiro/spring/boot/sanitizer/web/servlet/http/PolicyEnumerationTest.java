package org.apache.shiro.spring.boot.sanitizer.web.servlet.http;

import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PolicyEnumeration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("PolicyEnumeration Tests")
class PolicyEnumerationTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        PolicyFactory factory = new HtmlPolicyBuilder().toFactory();
        Enumeration<String> headers = Collections.enumeration(Arrays.asList("test"));
        PolicyEnumeration instance = new PolicyEnumeration(headers, factory);
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("hasMoreElements delegates to wrapped enumeration")
    void testHasMoreElements() {
        PolicyFactory factory = new HtmlPolicyBuilder().toFactory();
        Enumeration<String> headers = Collections.enumeration(Arrays.asList("a", "b"));
        PolicyEnumeration pe = new PolicyEnumeration(headers, factory);
        assertThat(pe.hasMoreElements()).isTrue();
        pe.nextElement();
        assertThat(pe.hasMoreElements()).isTrue();
        pe.nextElement();
        assertThat(pe.hasMoreElements()).isFalse();
    }

    @Test
    @DisplayName("nextElement sanitizes header values")
    void testNextElement() {
        PolicyFactory factory = new HtmlPolicyBuilder().toFactory();
        Enumeration<String> headers = Collections.enumeration(Arrays.asList("safe-value"));
        PolicyEnumeration pe = new PolicyEnumeration(headers, factory);
        String result = pe.nextElement();
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("nextElement strips XSS from header values")
    void testNextElementStripsXss() {
        PolicyFactory factory = new HtmlPolicyBuilder().toFactory();
        Enumeration<String> headers = Collections.enumeration(Arrays.asList("<script>alert('xss')</script>"));
        PolicyEnumeration pe = new PolicyEnumeration(headers, factory);
        String result = pe.nextElement();
        assertThat(result).doesNotContain("<script>");
    }
}
