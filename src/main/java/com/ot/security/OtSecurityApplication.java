package com.ot.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class OtSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(OtSecurityApplication.class, args);
    }

}
