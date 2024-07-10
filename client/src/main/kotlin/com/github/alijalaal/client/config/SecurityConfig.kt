package com.github.alijalaal.client.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class SecurityConfig {
  @Bean
  fun webSecurityCustomizer(): WebSecurityCustomizer {
    return WebSecurityCustomizer { web: WebSecurity -> web.ignoring().requestMatchers("/webjars/**", "/assets/**") }
  }

  // @formatter:off
  @Bean
  @Throws(Exception::class)
  fun securityFilterChain(http:HttpSecurity, clientRegistrationRepository:ClientRegistrationRepository): SecurityFilterChain {
    http
      .authorizeHttpRequests(Customizer {authorize -> authorize
        .requestMatchers("/logged-out").permitAll()
        .anyRequest().authenticated()}
      )
      .oauth2Login{oauth2Login:OAuth2LoginConfigurer<HttpSecurity?> -> oauth2Login.loginPage("/oauth2/authorization/messaging-client-oidc")}
      .oauth2Client(Customizer.withDefaults())
      .logout{logout:LogoutConfigurer<HttpSecurity?> -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))}
    return http.build()
  }

  // @formatter:on
  private fun oidcLogoutSuccessHandler(clientRegistrationRepository: ClientRegistrationRepository): LogoutSuccessHandler {
    val oidcLogoutSuccessHandler = OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository)

    // Set the location that the End-User's User Agent will be redirected to
    // after the logout has been performed at the Provider
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logged-out")

    return oidcLogoutSuccessHandler
  }
}