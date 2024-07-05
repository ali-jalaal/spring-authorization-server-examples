package com.github.alijalaal.resourceserver.config

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
class ResourceServerConfig {
  // @formatter:off
  @org.springframework.context.annotation.Bean @kotlin.Throws(java.lang.Exception::class) fun securityFilterChain(http:HttpSecurity): SecurityFilterChain {
    http
      .securityMatcher("/messages/**")
        .authorizeHttpRequests()
          .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
          .and()
        .oauth2ResourceServer()
          .jwt()
    return http.build()
  } // @formatter:on
}
