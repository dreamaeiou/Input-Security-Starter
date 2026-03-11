package org.example.input_security_starter.engine;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 输入规范化工具类
 * 用于处理各种编码绕过技巧，防止攻击者通过编码方式绕过安全检测。
 * 
 * 支持的编码类型：
 * 1. URL 编码（单次和双重编码）- %3C -> <
 * 2. Unicode 编码 - \u003c -> <
 * 3. HTML 实体编码（十进制和十六进制）- &#60; &#x3c; -> <
 * 4. Base64 编码 - 自动检测并解码
 * 5. 全角字符 - ＜ -> <
 * 6. 空字节 - \x00 -> (移除)
 * 7. 空白字符变体 - 制表符、换行符等规范化为空格
 * 8. 混合编码组合攻击
 * 
 * 处理流程：
 * 原始输入 -> 移除空字节 -> 全角转半角 -> URL解码 -> Unicode解码 
 *          -> HTML实体解码 -> Base64解码 -> 混合编码处理 -> 空白字符规范化
 */
public class InputNormalizer {

    /** HTML 实体编码模式 - 十进制格式，如 &#60; */
    private static final Pattern HTML_ENTITY_DECIMAL = Pattern.compile("&#(\\d+);?");
    /** HTML 实体编码模式 - 十六进制格式，如 &#x3c; */
    private static final Pattern HTML_ENTITY_HEX = Pattern.compile("&#x([0-9a-fA-F]+);?");
    /** Unicode 转义序列模式，如 \u003c */
    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9a-fA-F]{4})");
    /** 空白字符变体模式（包括制表符、换行符、回车符等控制字符） */
    private static final Pattern WHITESPACE_VARIANTS = Pattern.compile("[\\x00-\\x20\\x7f]+");
    /** 空字节模式，用于移除空字节截断攻击 */
    private static final Pattern NULL_BYTES = Pattern.compile("\\x00");
    /** Base64 编码模式（至少 8 个字符，更严格以减少误报） */
    private static final Pattern BASE64_PATTERN = Pattern.compile("[A-Za-z0-9+/]{8,}={0,2}");
    /** 全角字符范围（FF00-FFEF） */
    private static final Pattern FULL_WIDTH_CHARS = Pattern.compile("[\\uFF00-\\uFFEF]");
    /** Base64 递归解码最大深度，防止无限递归 */
    private static final int MAX_BASE64_RECURSION_DEPTH = 5;
    
    /**
     * 对输入进行规范化处理
     * 按顺序执行多种解码操作，处理混合编码攻击
     * 
     * @param input 原始输入字符串
     * @return 规范化后的输入字符串
     */
    public static String normalize(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        String normalized = input;
        
        // 1. 移除空字节（防止空字节截断绕过）
        normalized = removeNullBytes(normalized);
        
        // 2. 全角转半角（处理全角字符绕过）
        normalized = fullWidthToHalfWidth(normalized);
        
        // 3. URL 解码（最多解码3次，处理双重编码）
        normalized = decodeUrl(normalized);
        
        // 4. Unicode 转义解码
        normalized = decodeUnicode(normalized);
        
        // 5. HTML 实体解码
        normalized = decodeHtmlEntities(normalized);
        
        // 6. Base64 解码（检测并解码可能的 Base64 编码）
        normalized = decodeBase64IfNeeded(normalized);
        
        // 7. 处理混合编码（Base64 解码后可能还有编码）
        if (hasEncoding(normalized)) {
            normalized = decodeUrl(normalized);
            normalized = decodeHtmlEntities(normalized);
        }
        
        // 8. 规范化空白字符
        normalized = normalizeWhitespace(normalized);
        
        return normalized;
    }
    
    /**
     * 移除空字节
     * 防止攻击者使用空字节截断绕过检测
     * @param input 输入字符串
     * @return 移除空字节后的字符串
     */
    private static String removeNullBytes(String input) {
        return NULL_BYTES.matcher(input).replaceAll("");
    }
    
    /**
     * URL 解码，支持多次解码
     * 最多解码 3 次，防止双重/三重编码绕过
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeUrl(String input) {
        String decoded = input;
        String previous;
        int maxAttempts = 3;
        
        for (int i = 0; i < maxAttempts; i++) {
            previous = decoded;
            try {
                decoded = URLDecoder.decode(decoded, StandardCharsets.UTF_8.name());
            } catch (IllegalArgumentException e) {
                // 解码失败（非法编码），返回当前结果
                break;
            } catch (UnsupportedEncodingException e) {
                // UTF-8 应该总是可用
                break;
            }
            
            // 如果解码后没有变化，停止解码
            if (decoded.equals(previous)) {
                break;
            }
        }
        
        return decoded;
    }
    
    /**
     * 解码 Unicode 转义序列
     * 将 \u003c 形式转换为对应字符
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeUnicode(String input) {
        Matcher matcher = UNICODE_ESCAPE.matcher(input);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            try {
                int codePoint = Integer.parseInt(matcher.group(1), 16);
                matcher.appendReplacement(result, String.valueOf((char) codePoint));
            } catch (NumberFormatException e) {
                matcher.appendReplacement(result, matcher.group(0));
            }
        }
        matcher.appendTail(result);
        
        return result.toString();
    }
    
    /**
     * 解码 HTML 实体编码
     * 包括十进制和十六进制格式
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeHtmlEntities(String input) {
        String result = input;
        
        // 解码十进制 HTML 实体 &#60; -> <
        result = decodeHtmlDecimalEntities(result);
        
        // 解码十六进制 HTML 实体 &#x3c; -> <
        result = decodeHtmlHexEntities(result);
        
        return result;
    }
    
    /**
     * 解码十进制 HTML 实体
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeHtmlDecimalEntities(String input) {
        Matcher matcher = HTML_ENTITY_DECIMAL.matcher(input);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            try {
                int codePoint = Integer.parseInt(matcher.group(1));
                matcher.appendReplacement(result, String.valueOf((char) codePoint));
            } catch (NumberFormatException e) {
                matcher.appendReplacement(result, matcher.group(0));
            }
        }
        matcher.appendTail(result);
        
        return result.toString();
    }
    
    /**
     * 解码十六进制 HTML 实体
     * @param input 输入字符串
     * @return 解码后的字符串
     */
    private static String decodeHtmlHexEntities(String input) {
        Matcher matcher = HTML_ENTITY_HEX.matcher(input);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            try {
                int codePoint = Integer.parseInt(matcher.group(1), 16);
                matcher.appendReplacement(result, String.valueOf((char) codePoint));
            } catch (NumberFormatException e) {
                matcher.appendReplacement(result, matcher.group(0));
            }
        }
        matcher.appendTail(result);
        
        return result.toString();
    }
    
    /**
     * 规范化空白字符
     * 将各种空白字符（制表符、换行符等）替换为普通空格
     * @param input 输入字符串
     * @return 规范化后的字符串
     */
    private static String normalizeWhitespace(String input) {
        return WHITESPACE_VARIANTS.matcher(input).replaceAll(" ");
    }
    
    /**
     * 全角字符转半角字符
     * 处理全角字符绕过技巧，如全角的＜script＞
     * @param input 输入字符串
     * @return 转换后的字符串
     */
    private static String fullWidthToHalfWidth(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        StringBuilder result = new StringBuilder(input.length());
        
        for (char c : input.toCharArray()) {
            // 全角空格 (U+3000) 转半角空格 (U+0020)
            if (c == '\u3000') {
                result.append(' ');
            }
            // 全角字符 (U+FF01-U+FF5E) 转半角字符 (U+0021-U+007E)
            else if (c >= '\uFF01' && c <= '\uFF5E') {
                result.append((char)(c - 0xFEE0));
            }
            // 其他字符保持不变
            else {
                result.append(c);
            }
        }
        
        return result.toString();
    }
    
    /**
     * 检测并解码 Base64 编码
     * 处理使用 Base64 编码绕过检测的攻击
     * @param input 输入字符串
     * @return 解码后的字符串（如果检测到 Base64）或原始字符串
     */
    private static String decodeBase64IfNeeded(String input) {
        return decodeBase64IfNeeded(input, 0);
    }
    
    /**
     * 递归解码 Base64 编码
     * 支持嵌套 Base64 解码，最大深度为 5 层
     * @param input 输入字符串
     * @param depth 当前递归深度
     * @return 解码后的字符串
     */
    private static String decodeBase64IfNeeded(String input, int depth) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        
        // 防止无限递归
        if (depth > MAX_BASE64_RECURSION_DEPTH) {
            return input;
        }
        
        Matcher matcher = BASE64_PATTERN.matcher(input);
        StringBuilder result = new StringBuilder();
        int lastEnd = 0;
        
        while (matcher.find()) {
            String base64Str = matcher.group();
            
            result.append(input, lastEnd, matcher.start());
            
            try {
                // 补齐 Base64 padding
                String paddedBase64 = base64Str;
                int paddingNeeded = (4 - base64Str.length() % 4) % 4;
                if (paddingNeeded > 0 && !base64Str.endsWith("=")) {
                    StringBuilder sb = new StringBuilder(base64Str);
                    for (int i = 0; i < paddingNeeded; i++) {
                        sb.append('=');
                    }
                    paddedBase64 = sb.toString();
                }
                
                byte[] decodedBytes = Base64.getDecoder().decode(paddedBase64);
                String decoded = new String(decodedBytes, StandardCharsets.UTF_8);
                
                // 只有解码后是可打印文本才接受
                if (isPrintableText(decoded)) {
                    result.append(decodeBase64IfNeeded(decoded, depth + 1));
                } else {
                    result.append(base64Str);
                }
            } catch (IllegalArgumentException e) {
                // 不是有效的 Base64，保留原文
                result.append(base64Str);
            }
            
            lastEnd = matcher.end();
        }
        
        result.append(input.substring(lastEnd));
        
        return result.toString();
    }
    
    /**
     * 检查字符串是否为可打印文本
     * 用于判断 Base64 解码结果是否有效
     * @param str 待检查的字符串
     * @return 是否为可打印文本（至少 70% 可打印字符）
     */
    private static boolean isPrintableText(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        
        int printableCount = 0;
        for (char c : str.toCharArray()) {
            if (Character.isLetterOrDigit(c) || 
                Character.isWhitespace(c) || 
                isPunctuation(c)) {
                printableCount++;
            }
        }
        
        return (double) printableCount / str.length() >= 0.7;
    }
    
    /**
     * 检查字符是否为常见标点符号
     * @param c 字符
     * @return 是否为标点符号
     */
    private static boolean isPunctuation(char c) {
        return c == '<' || c == '>' || c == '=' || c == '"' || c == '\'' ||
               c == '/' || c == '\\' || c == '(' || c == ')' || c == '[' ||
               c == ']' || c == '{' || c == '}' || c == ';' || c == ':' ||
               c == ',' || c == '.' || c == '!' || c == '?' || c == '&' ||
               c == '|' || c == '+' || c == '-' || c == '*' || c == '@' ||
               c == '#' || c == '$' || c == '%' || c == '^' || c == '_' ||
               c == '`' || c == '~';
    }
    
    /**
     * 检查输入是否包含编码特征
     * 用于判断是否需要进一步解码处理
     * @param input 输入字符串
     * @return 是否包含编码特征
     */
    public static boolean hasEncoding(String input) {
        if (input == null) {
            return false;
        }
        
        return input.contains("%") ||  // URL 编码
               input.contains("&#") || // HTML 实体
               input.contains("\\u") || // Unicode 转义
               input.contains("\\x") || // 十六进制转义
               BASE64_PATTERN.matcher(input).find() || // Base64 编码
               hasFullWidthChars(input); // 全角字符
    }
    
    /**
     * 检查输入是否包含全角字符
     * @param input 输入字符串
     * @return 是否包含全角字符
     */
    private static boolean hasFullWidthChars(String input) {
        for (char c : input.toCharArray()) {
            if (c == '\u3000') {
                return true;
            }
            Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
            if (block == Character.UnicodeBlock.CJK_COMPATIBILITY_FORMS ||
                block == Character.UnicodeBlock.CJK_COMPATIBILITY ||
                block == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS) {
                return true;
            }
        }
        return false;
    }
}
