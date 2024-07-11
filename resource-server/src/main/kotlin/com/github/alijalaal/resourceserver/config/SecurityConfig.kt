package com.github.alijalaal.resourceserver.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class ResourceServerConfig {
  // @formatter:off
  @Bean @kotlin.Throws(Exception::class) fun securityFilterChain(http:HttpSecurity): SecurityFilterChain {
    http
      .securityMatcher("/messages/**")
        .authorizeHttpRequests{t -> t.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")}
        .oauth2ResourceServer{t -> t.jwt{c -> c}}
    return http.build()
  } // @formatter:on
}
