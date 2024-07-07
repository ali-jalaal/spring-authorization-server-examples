package com.github.alijalaal.authserver.config


import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.session.HttpSessionEventPublisher

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class DefaultSecurityConfig {
  // @formatter:off
  @Order(2)
  @Bean @Throws(Exception::class) fun defaultSecurityFilterChain(http:HttpSecurity): SecurityFilterChain {
    http
      .authorizeHttpRequests{authorize -> authorize
        .requestMatchers("/assets/**", "/login").permitAll()
        .anyRequest().authenticated()}
      .formLogin{formLogin:FormLoginConfigurer<HttpSecurity?> -> formLogin
        .loginPage("/login")}
//      .oauth2Login{oauth2Login:OAuth2LoginConfigurer<HttpSecurity?> -> oauth2Login
//        .loginPage("/login")
//        .successHandler(authenticationSuccessHandler())}

    return http.build()
  }

  // @formatter:on
/*
  private fun authenticationSuccessHandler(): AuthenticationSuccessHandler {
    return FederatedIdentityAuthenticationSuccessHandler()
  }
*/

  // @formatter:off
  @Bean
  fun users(): UserDetailsService {
    val user = User.withDefaultPasswordEncoder()
      .username("user1")
      .password("password")
      .roles("USER")
      .build()
    return InMemoryUserDetailsManager(user)
  }

  // @formatter:on
  @Bean
  fun sessionRegistry(): SessionRegistry {
    return SessionRegistryImpl()
  }

  @Bean
  fun httpSessionEventPublisher(): HttpSessionEventPublisher {
    return HttpSessionEventPublisher()
  }
}
