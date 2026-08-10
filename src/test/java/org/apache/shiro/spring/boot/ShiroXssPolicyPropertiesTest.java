package org.apache.shiro.spring.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ShiroXssPolicyProperties}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("ShiroXssPolicyProperties Tests")
class ShiroXssPolicyPropertiesTest {

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPrefixConstant() {
        assertThat(ShiroXssPolicyProperties.PREFIX).isEqualTo("shiro.xss-policy");
    }

    @Test
    @DisplayName("Default values are correct")
    void testDefaultValues() {
        ShiroXssPolicyProperties props = new ShiroXssPolicyProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getPolicyHeaders()).isNull();
    }

    @Test
    @DisplayName("enabled getter/setter works correctly")
    void testEnabledGetterSetter() {
        ShiroXssPolicyProperties props = new ShiroXssPolicyProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
        props.setEnabled(false);
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("policyHeaders getter/setter works correctly")
    void testPolicyHeadersGetterSetter() {
        ShiroXssPolicyProperties props = new ShiroXssPolicyProperties();
        String[] headers = {"X-Custom-Header", "Authorization"};
        props.setPolicyHeaders(headers);
        assertThat(props.getPolicyHeaders()).isEqualTo(headers);
        assertThat(props.getPolicyHeaders()).hasSize(2);
    }

    @Test
    @DisplayName("policyHeaders can be set to null")
    void testPolicyHeadersNull() {
        ShiroXssPolicyProperties props = new ShiroXssPolicyProperties();
        props.setPolicyHeaders(new String[]{"test"});
        props.setPolicyHeaders(null);
        assertThat(props.getPolicyHeaders()).isNull();
    }
}
