package com.todolist.apigateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import com.todolist.apigateway.util.JwtUtil;

import io.jsonwebtoken.Claims;

import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // Bypass authentication for the login endpoint
            if (request.getURI().getPath().startsWith("/api/auth/login")) {
                return chain.filter(exchange);
            }

            if (validator.isSecured.test(request)) {
                // Check for Authorization header
                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Missing Authorization Header".getBytes())));
                }

                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                    try {
                        // Validate the token
                        jwtUtil.validateToken(authHeader);

                        Claims claims = jwtUtil.getAllClaimsFromToken(authHeader);
                        List<String> roles = claims.get("roles", List.class);

                        // Check if roles or config.getRole() is null
                        if (roles == null) {
                            logger.warn("Roles in token are null");
                            response.setStatusCode(HttpStatus.UNAUTHORIZED);
                            return response.writeWith(Mono.just(response.bufferFactory().wrap("Roles not found in token".getBytes())));
                        }

                        if (config.getRole() == null) {
                            logger.warn("Required roles are not defined in configuration");
                            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            return response.writeWith(Mono.just(response.bufferFactory().wrap("Internal Server Error".getBytes())));
                        }

                        // Check if the role is valid and allowed
                        if (!roles.containsAll(config.getRole())) {
                            logger.warn("Access Denied: Required roles not found in token");
                            response.setStatusCode(HttpStatus.FORBIDDEN);
                            return response.writeWith(Mono.just(response.bufferFactory().wrap("Access Denied".getBytes())));
                        }

                    } catch (Exception e) {
                        logger.error("Invalid JWT Token", e);
                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
                        return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid JWT Token".getBytes())));
                    }
                } else {
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid Authorization Header".getBytes())));
                }
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {
        private Set<String> role;

        public Set<String> getRole() {
            return role;
        }

        public void setRole(Set<String> role) {
            this.role = role;
        }
    }
}


//package com.todolist.apigateway.filter;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//
//import com.todolist.apigateway.util.JwtUtil;
//
//import io.jsonwebtoken.Claims;
//
//import java.util.List;
//import java.util.Set;
//
//@Component
//public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
//
//    @Autowired
//    private RouteValidator validator;
//
//    @Autowired
//    private JwtUtil jwtUtil;
//
//    public AuthenticationFilter() {
//        super(Config.class);
//    }
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//            ServerHttpResponse response = exchange.getResponse();
//
//            // Bypass authentication for the login endpoint
//            if (request.getURI().getPath().startsWith("/api/auth/login")) {
//                return chain.filter(exchange);
//            }
//
//            if (validator.isSecured.test(request)) {
//                // Check for Authorization header
//                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Missing Authorization Header".getBytes())));
//                }
//
//                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
//                if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                    authHeader = authHeader.substring(7);
//                    try {
//                        // Validate the token
//                        jwtUtil.validateToken(authHeader);
//                       
//                        Claims claims = jwtUtil.getAllClaimsFromToken(authHeader);
//                        List<String> roles = claims.get("roles", List.class);
//                        System.out.println(roles);
//
//                        // Check if the role is valid and allowed
//                        if (roles == null || !roles.contains(config.getRole())) {
//                        	System.out.println(!roles.contains(config.getRole()));
//                            response.setStatusCode(HttpStatus.FORBIDDEN);
//                            return response.writeWith(Mono.just(response.bufferFactory().wrap("Access Denied".getBytes())));
//                        }
//
//                    } catch (Exception e) {
//                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                        return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid JWT Token".getBytes())));
//                    }
//                } else {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid Authorization Header".getBytes())));
//                }
//            }
//
//            return chain.filter(exchange);
//        };
//    }
//
//    public static class Config {
//        private Set<String> role;
//
//		public Set<String> getRole() {
//			return role;
//		}
//
//		public void setRole(Set<String> role) {
//			this.role = role;
//		}
//    }
//}


//package com.todolist.apigateway.filter;
//
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Map;
//import java.util.Set;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//import com.todolist.apigateway.util.JwtUtil;
//import io.jsonwebtoken.Claims;
//
//@Component
//public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
//
//    @Autowired
//    private RouteValidator validator;
//
//    @Autowired
//    private JwtUtil jwtUtil;
//
//    public AuthenticationFilter() {
//        super(Config.class);
//    }
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//            ServerHttpResponse response = exchange.getResponse();
//
//            // Bypass authentication for the login endpoint
//            if (request.getURI().getPath().startsWith("/api/auth/login")) {
//                return chain.filter(exchange);
//            }
//
//            if (validator.isSecured.test(request)) {
//                // Check for Authorization header
//                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Missing Authorization Header".getBytes())));
//                }
//
//                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
//                if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                    authHeader = authHeader.substring(7);
//                    try {
//                        // Validate the token
//                        jwtUtil.validateToken(authHeader);
//                       
//                        Claims claims = jwtUtil.getAllClaimsFromToken(authHeader);
//                        String role = claims.get("roles", String.class);
//                        
//                        Object roleObject= claims.get("roles");
//                        
//                        List<String> role1= new ArrayList<>();
//                        
//                        List<Map<String, String>> authorities = (List<Map<String, String>>) roleObject;
//                       
//                        
//                      
//
////                        // Check if the role is valid and allowed
////                        if (role == null || !config.getRole().equals(role)) {
////                            response.setStatusCode(HttpStatus.FORBIDDEN);
////                            return response.writeWith(Mono.just(response.bufferFactory().wrap("Access Denied".getBytes())));}
//
//                    } catch (Exception e) {
//                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                        return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid JWT Token".getBytes())));
//                    }
//                } else {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid Authorization Header".getBytes())));
//                }
//            }
//
//            return chain.filter(exchange);
//        };
//    }
//
//    public static class Config {
//        private String role;
//
//        public String getRole() {
//            return role;
//        }
//
//        public void setRole(String role) {
//            this.role = role;
//        }
//    }
//}



//package com.todolist.apigateway.filter;
//
//import java.util.Set;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//
//import com.thoughtworks.xstream.mapper.Mapper.Null;
//import com.todolist.apigateway.util.JwtUtil;
//
//import io.jsonwebtoken.Claims;
//
//@Component
//public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
//
//    @Autowired
//    private RouteValidator validator;
//
//    @Autowired
//    private JwtUtil jwtUtil;
//
//    public AuthenticationFilter() {
//        super(Config.class);
//    }
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//            ServerHttpResponse response = exchange.getResponse();
//
//            // Bypass authentication for the login endpoint
//            if (request.getURI().getPath().startsWith("/api/auth/login")) {
//                return chain.filter(exchange);
//            }
//
//            if (validator.isSecured.test(request)) {
//                // Check for Authorization header
//                if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Missing Authorization Header".getBytes())));
//                }
//
//                String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
//                if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                    authHeader = authHeader.substring(7);
//                    try {
//                        // Validate the token
//                        jwtUtil.validateToken(authHeader);
//                        
//                        Claims getRole = jwtUtil.getAllClaimsFromToken(authHeader);
//                        System.out.println("////////////////"+getRole);
//                        
//                        Object role = getRole.get("roles");
//                        System.out.println("Roles"+role);
//                        
//                        System.out.println(config.getRole());
//                        
//                        if(role == null || !role.equals(config.getRole()))
//                        {
//                        	throw new Exception("Not Valid");
//                        }
//                        
//                    } catch (Exception e) {
//                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                        return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid JWT Token".getBytes())));
//                    }
//                } else {
//                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
//                    return response.writeWith(Mono.just(response.bufferFactory().wrap("Invalid Authorization Header".getBytes())));
//                }
//            }
//
//            return chain.filter(exchange);
//        };
//    }
//    public static class Config {
//    	
//    	private Set<String> role;
//
//		public Set<String> getRole() {
//			return role;
//		}
//
//		public void setRole(Set<String> role) {
//			this.role = role;
//		}
//    }
//}
/////////////////////////////////////////////////////////////////////////////////////////////
//package com.todolist.apigateway.filter;
//
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.stereotype.Component;
//
//
//import com.todolist.apigateway.util.JwtUtil;
//
//@Component
//public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
//
//    @Autowired
//    private RouteValidator validator;
//
//    @Autowired
//    private JwtUtil jwtUtil;
//
//    public AuthenticationFilter() {
//        super(Config.class);
//    }
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return ((exchange, chain) -> {
//            if (validator.isSecured.test(exchange.getRequest())) {
//                //header contains token or not
//                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
//                    throw new RuntimeException("missing authorization header");
//                }
//
//                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
//                if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                    authHeader = authHeader.substring(7);
//                }
//                try {
////                    //REST call to AUTH service
////                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
//                    jwtUtil.validateToken(authHeader);
//
//                } catch (Exception e) {
//                    System.out.println("invalid access...!");
//                    throw new RuntimeException("un authorized access to application");
//                }
//            }
//            return chain.filter(exchange);
//        });
//    }
//
//    public static class Config {
//
//    }
//}