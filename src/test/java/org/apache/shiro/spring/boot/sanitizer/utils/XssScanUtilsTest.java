package org.apache.shiro.spring.boot.sanitizer.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link XssScanUtils}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("XssScanUtils Tests")
class XssScanUtilsTest {

    @Test
    @DisplayName("isXssHeader returns false when policyHeaders is null")
    void testIsXssHeaderNullHeaders() {
        assertThat(XssScanUtils.isXssHeader(null, "X-Test")).isFalse();
    }

    @Test
    @DisplayName("isXssHeader returns false when policyHeaders is empty")
    void testIsXssHeaderEmptyHeaders() {
        assertThat(XssScanUtils.isXssHeader(new String[]{}, "X-Test")).isFalse();
    }

    @Test
    @DisplayName("isXssHeader returns true when header is in policy list")
    void testIsXssHeaderFound() {
        String[] headers = {"X-Custom", "Authorization"};
        assertThat(XssScanUtils.isXssHeader(headers, "X-Custom")).isTrue();
        assertThat(XssScanUtils.isXssHeader(headers, "Authorization")).isTrue();
    }

    @Test
    @DisplayName("isXssHeader returns false when header is not in policy list")
    void testIsXssHeaderNotFound() {
        String[] headers = {"X-Custom"};
        assertThat(XssScanUtils.isXssHeader(headers, "X-Other")).isFalse();
    }

    @Test
    @DisplayName("isXssHeader returns false when header name is null")
    void testIsXssHeaderNullName() {
        String[] headers = {"X-Custom"};
        assertThat(XssScanUtils.isXssHeader(headers, null)).isFalse();
    }
}
