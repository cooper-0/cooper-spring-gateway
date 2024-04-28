package com.whisper.coopergateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class CooperGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(CooperGatewayApplication.class, args);
	}

}
