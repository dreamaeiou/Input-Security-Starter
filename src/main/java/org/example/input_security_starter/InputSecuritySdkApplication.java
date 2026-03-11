package org.example.input_security_starter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

/**
 * Spring Boot 主应用类
 * 使用@ComponentScan 排除 web 包下的控制器，避免与 InputSecurityAutoConfiguration 中的 Bean 定义冲突
 */
@SpringBootApplication
@ComponentScan(excludeFilters = {
    @ComponentScan.Filter(
        pattern = "org.example.input_security_starter.web.*",
        type = FilterType.REGEX
    )
})
public class InputSecuritySdkApplication {

    public static void main(String[] args) {
        SpringApplication.run(InputSecuritySdkApplication.class, args);
    }

}