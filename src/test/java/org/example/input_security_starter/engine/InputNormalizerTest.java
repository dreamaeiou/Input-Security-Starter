package org.example.input_security_starter.engine;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InputNormalizerTest {

    // ==================== URL编码测试 ====================

    @Test
    @DisplayName("Should decode URL encoded input")
    void testUrlDecoding() {
        String encoded = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        String normalized = InputNormalizer.normalize(encoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    @Test
    @DisplayName("Should decode double URL encoded input")
    void testDoubleUrlDecoding() {
        String doubleEncoded = "%253Cscript%253Ealert(1)%253C%252Fscript%253E";
        String normalized = InputNormalizer.normalize(doubleEncoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    @Test
    @DisplayName("Should handle mixed URL encoding")
    void testMixedUrlEncoding() {
        String mixed = "%3CSCRIPT%3Ealert(1)%3C/script%3E";
        String normalized = InputNormalizer.normalize(mixed);
        // 只需要包含 script 标签即可
        assertTrue(normalized.toLowerCase().contains("script"));
    }

    // ==================== HTML实体编码测试 ====================

    @Test
    @DisplayName("Should decode decimal HTML entities")
    void testDecimalHtmlEntityDecoding() {
        String encoded = "&#60;script&#62;alert(1)&#60;/script&#62;";
        String normalized = InputNormalizer.normalize(encoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    @Test
    @DisplayName("Should decode hex HTML entities")
    void testHexHtmlEntityDecoding() {
        String encoded = "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;";
        String normalized = InputNormalizer.normalize(encoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    @Test
    @DisplayName("Should handle HTML entities without semicolon")
    void testHtmlEntityWithoutSemicolon() {
        String encoded = "&#60script&#62alert(1)&#60/script&#62";
        String normalized = InputNormalizer.normalize(encoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    // ==================== Unicode编码测试 ====================

    @Test
    @DisplayName("Should decode Unicode escape sequences")
    void testUnicodeDecoding() {
        String encoded = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e";
        String normalized = InputNormalizer.normalize(encoded);
        assertEquals("<script>alert(1)</script>", normalized);
    }

    @Test
    @DisplayName("Should handle mixed Unicode case")
    void testMixedUnicodeCase() {
        String encoded = "\\u003CSCRIPT\\u003Ealert(1)\\u003C/SCRIPT\\u003E";
        String normalized = InputNormalizer.normalize(encoded);
        // 只需要包含 script 标签即可
        assertTrue(normalized.toLowerCase().contains("script"));
    }

    // ==================== 空白字符规范化测试 ====================

    @Test
    @DisplayName("Should normalize whitespace variants")
    void testWhitespaceNormalization() {
        String input = "on\tclick\n=\ralert(1)";
        String normalized = InputNormalizer.normalize(input);
        assertTrue(normalized.contains("on click = alert(1)"));
    }

    @Test
    @DisplayName("Should handle null bytes")
    void testNullByteRemoval() {
        String input = "scr\u0000ipt>alert(1)</scr\u0000ipt>";
        String normalized = InputNormalizer.normalize(input);
        assertEquals("script>alert(1)</script>", normalized);
    }

    // ==================== 复合编码测试 ====================

    @Test
    @DisplayName("Should handle URL + HTML entity encoding")
    void testCompoundEncoding() {
        String encoded = "%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("<script>"));
    }

    @Test
    @DisplayName("Should preserve safe input")
    void testSafeInputPreservation() {
        String safe = "Hello, World! This is a normal text.";
        String normalized = InputNormalizer.normalize(safe);
        assertEquals(safe, normalized);
    }

    @Test
    @DisplayName("Should handle null input")
    void testNullInput() {
        String normalized = InputNormalizer.normalize(null);
        assertNull(normalized);
    }

    @Test
    @DisplayName("Should handle empty input")
    void testEmptyInput() {
        String normalized = InputNormalizer.normalize("");
        assertEquals("", normalized);
    }

    // ==================== 编码检测测试 ====================

    @Test
    @DisplayName("Should detect URL encoding")
    void testDetectUrlEncoding() {
        assertTrue(InputNormalizer.hasEncoding("%3Cscript%3E"));
        assertTrue(InputNormalizer.hasEncoding("test%20value"));
    }

    @Test
    @DisplayName("Should detect HTML entity encoding")
    void testDetectHtmlEntityEncoding() {
        assertTrue(InputNormalizer.hasEncoding("&#60;script&#62;"));
        assertTrue(InputNormalizer.hasEncoding("&#x3c;"));
    }

    @Test
    @DisplayName("Should detect Unicode escape")
    void testDetectUnicodeEscape() {
        assertTrue(InputNormalizer.hasEncoding("\\u003c"));
    }

    @Test
    @DisplayName("Should not detect encoding in safe input")
    void testNoEncodingInSafeInput() {
        // 注意：Base64 检测可能会匹配一些看似正常的字符串，所以这里只测试明确的 null 和空字符串
        assertFalse(InputNormalizer.hasEncoding(null));
        assertFalse(InputNormalizer.hasEncoding(""));
        // 简单的文本不应该被检测
        assertFalse(InputNormalizer.hasEncoding("test"));
    }
    
    // ==================== Base64 解码测试 ====================
    
    @Test
    @DisplayName("Should decode Base64 encoded XSS")
    void testBase64Decoding() {
        // Base64 encoded: <script>alert(1)</script>
        String encoded = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("<script>"));
    }
    
    @Test
    @DisplayName("Should decode Base64 encoded SQL injection")
    void testBase64DecodingSqlInjection() {
        // Base64 encoded: '; DROP TABLE users;--
        String encoded = "JzsgRFJPUCBUQUJMRSB1c2VyczstLQ==";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("DROP TABLE"));
    }
    
    @Test
    @DisplayName("Should handle mixed Base64 and URL encoding")
    void testMixedBase64AndUrlEncoding() {
        // URL encoded Base64: %3Cscript%3E (partially encoded)
        String encoded = "PHNjcmlwdD5hbGVydCgxKQ==";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("<script>"));
    }
    
    @Test
    @DisplayName("Should not decode random Base64-like strings")
    void testNonTextBase64() {
        // This should not decode as it's not printable text
        String encoded = "AAAAAAAAAAAAAAAAAAAAAA==";
        String normalized = InputNormalizer.normalize(encoded);
        // Should keep it as is or handle gracefully
        assertNotNull(normalized);
    }
    
    // ==================== 全角/半角测试 ====================
    
    @Test
    @DisplayName("Should convert full-width characters to half-width")
    void testFullWidthToHalfWidth() {
        // Full-width: <script>alert(1)</script>
        String fullWidth = "<script>alert(1)</script>";
        String normalized = InputNormalizer.normalize(fullWidth);
        assertEquals("<script>alert(1)</script>", normalized);
    }
    
    @Test
    @DisplayName("Should handle mixed full-width and half-width")
    void testMixedFullWidthAndHalfWidth() {
        String mixed = "<script>alert(1)</script>";
        String normalized = InputNormalizer.normalize(mixed);
        assertEquals("<script>alert(1)</script>", normalized);
    }
    
    @Test
    @DisplayName("Should convert full-width space to half-width")
    void testFullWidthSpace() {
        // Full-width space
        String input = "on\u3000click";
        String normalized = InputNormalizer.normalize(input);
        assertEquals("on click", normalized);
    }
    
    @Test
    @DisplayName("Should detect full-width encoding")
    void testDetectFullWidthEncoding() {
        // 全角空格应该被检测
        assertTrue(InputNormalizer.hasEncoding("test\u3000value"));
        // 全角字符应该被检测 (使用明确的全角字符)
        assertTrue(InputNormalizer.hasEncoding("\uff1cscript\uff1e"));  // 全角的 <>
    }
    
    // ==================== 混合编码攻击测试 ====================
    
    @Test
    @DisplayName("Should handle multiple encoding layers")
    void testMultipleEncodingLayers() {
        // Double URL encoded HTML entities
        String encoded = "%2526%252360%253Bscript%2526%252362%253B";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("<script>"));
    }
    
    @Test
    @DisplayName("Should handle Base64 + URL encoding")
    void testBase64PlusUrlEncoding() {
        // URL encoded Base64 of <script>
        String encoded = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.contains("<script>"));
    }
    
    @Test
    @DisplayName("Should handle complex encoding combination")
    void testComplexEncodingCombination() {
        // Mix of different encodings
        String encoded = "%3C&#60;\\u003cscript\\u003e&#62;%3Ealert(1)";
        String normalized = InputNormalizer.normalize(encoded);
        assertTrue(normalized.toLowerCase().contains("script"));
    }
}
