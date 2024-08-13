//package com.todolist.apigateway;
//
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
//
//@SpringBootApplication
//@EnableDiscoveryClient
//public class ApiGateWayApplication {
//
//	public static void main(String[] args) {
//		SpringApplication.run(ApiGateWayApplication.class, args);
//	}
//	
//
//}
package com.todolist.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.resolver.DefaultAddressResolverGroup;
import reactor.netty.http.client.HttpClient;


@SpringBootApplication
@EnableDiscoveryClient
public class ApiGateWayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGateWayApplication.class, args);
    }

//    @Bean
//    @Primary
//    public WebClient webClient() {
//        HttpClient httpClient = HttpClient.create()
//            .resolver(DefaultAddressResolverGroup.INSTANCE);
//
//        return WebClient.builder()
//            .clientConnector(new ReactorClientHttpConnector(httpClient))
//            .build();
//    }
}
