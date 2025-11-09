package com.ot.security.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI otSecurityOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("OT 보안 모니터링 시스템 API")
                        .description("OT(Operational Technology) 환경의 보안 위협을 실시간으로 모니터링하고 관리하는 시스템의 REST API 문서입니다.")
                        .version("v1.0.0")
                        .contact(new Contact()
                                .name("OT Security Team")
                                .email("security@example.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080")
                                .description("개발 서버"),
                        new Server()
                                .url("http://localhost:8080")
                                .description("프로덕션 서버")
                ));
    }
}