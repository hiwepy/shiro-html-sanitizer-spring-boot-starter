package org.apache.shiro.spring.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.html.PolicyFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ShiroXssPolicyWebFilterConfiguration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("ShiroXssPolicyWebFilterConfiguration Tests")
class ShiroXssPolicyWebFilterConfigurationTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        ShiroXssPolicyWebFilterConfiguration instance = new ShiroXssPolicyWebFilterConfiguration();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("policyFactory bean creates a non-null PolicyFactory")
    void testPolicyFactory() {
        ShiroXssPolicyWebFilterConfiguration config = new ShiroXssPolicyWebFilterConfiguration();
        PolicyFactory factory = config.policyFactory();
        assertThat(factory).isNotNull();
    }

    @Test
    @DisplayName("xssPolicyFilter bean creates a FilterRegistrationBean")
    void testXssPolicyFilter() {
        ShiroXssPolicyWebFilterConfiguration config = new ShiroXssPolicyWebFilterConfiguration();
        PolicyFactory factory = config.policyFactory();
        ShiroXssPolicyProperties properties = new ShiroXssPolicyProperties();
        properties.setPolicyHeaders(new String[]{"X-Test"});
        var registration = config.xssPolicyFilter(factory, properties);
        assertThat(registration).isNotNull();
        assertThat(registration.getFilter()).isNotNull();
        assertThat(registration.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("xssPolicyFilter bean with null policyHeaders")
    void testXssPolicyFilterNullHeaders() {
        ShiroXssPolicyWebFilterConfiguration config = new ShiroXssPolicyWebFilterConfiguration();
        PolicyFactory factory = config.policyFactory();
        ShiroXssPolicyProperties properties = new ShiroXssPolicyProperties();
        var registration = config.xssPolicyFilter(factory, properties);
        assertThat(registration).isNotNull();
        assertThat(registration.getFilter()).isNotNull();
    }
}
