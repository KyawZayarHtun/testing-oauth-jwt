package com.kzyt;

import com.kzyt.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {RsaKeyProperties.class})
public class OatuhJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(OatuhJwtApplication.class, args);
	}

}
