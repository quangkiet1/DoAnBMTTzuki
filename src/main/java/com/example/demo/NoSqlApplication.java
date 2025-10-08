package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.example.demo.security.AESUtil;

@SpringBootApplication
public class NoSqlApplication {

	public static void main(String[] args) {
		SpringApplication.run(NoSqlApplication.class, args);
		AESUtil.hybridKeyEncryptionDemo();
	}

}
