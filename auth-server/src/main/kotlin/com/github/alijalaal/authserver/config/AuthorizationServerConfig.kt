/*
 * Copyright 2020-2023 the original author or authors.
 * Modifications copyright (c) 2024 Ali Jalal
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.alijalaal.authserver.config

import com.github.alijalaal.authserver.authentication.DeviceClientAuthenticationProvider
import com.github.alijalaal.authserver.federation.FederatedIdentityIdTokenCustomizer
import com.github.alijalaal.authserver.jose.Jwks
import com.github.alijalaal.authserver.web.authentication.DeviceClientAuthenticationConverter
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.*
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.*

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
@Configuration
@EnableWebSecurity
// @Import(OAuth2AuthorizationServerConfiguration::class) // Use this annotation for minimal OAuth2 configuration (authorizationServerSecurityFilterChain()')
class AuthorizationServerConfig {

  @Bean
  @Order(1)
  @Throws(Exception::class)
  fun authorizationServerSecurityFilterChain(
    http: HttpSecurity, registeredClientRepository: RegisteredClientRepository,
    authorizationServerSettings: AuthorizationServerSettings
  ): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)


    /*
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * The following components show how to customize the authorization
		 * server to allow for device clients to perform requests to the
		 * OAuth 2.0 Device Authorization Endpoint and Token Endpoint without
		 * a clientId/clientSecret.
		 *
		 * CAUTION: These endpoints will not require any authentication, and can
		 * be accessed by any client that has a valid clientId.
		 *
		 * It is therefore RECOMMENDED to carefully monitor the use of these
		 * endpoints and employ any additional protections as needed, which is
		 * outside the scope of this sample.
		 */
    val deviceClientAuthenticationConverter =
      DeviceClientAuthenticationConverter(
        authorizationServerSettings.deviceAuthorizationEndpoint
      )
    val deviceClientAuthenticationProvider =
      DeviceClientAuthenticationProvider(registeredClientRepository)

    http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
    // @formatter:off
    http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
      .deviceAuthorizationEndpoint{deviceAuthorizationEndpoint:OAuth2DeviceAuthorizationEndpointConfigurer -> deviceAuthorizationEndpoint.verificationUri("/activate")}
      .deviceVerificationEndpoint{deviceVerificationEndpoint:OAuth2DeviceVerificationEndpointConfigurer -> deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)}
      .clientAuthentication{clientAuthentication:OAuth2ClientAuthenticationConfigurer -> clientAuthentication
        .authenticationConverter(deviceClientAuthenticationConverter)
        .authenticationProvider(deviceClientAuthenticationProvider)}
      .authorizationEndpoint{authorizationEndpoint:OAuth2AuthorizationEndpointConfigurer -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)}
      .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
    // @formatter:on

    // @formatter:off
    // Redirect to the login page when not authenticated from the authorization endpoint
    http
      .exceptionHandling { exceptions ->
        exceptions
          .defaultAuthenticationEntryPointFor(
            LoginUrlAuthenticationEntryPoint("/login"),
            MediaTypeRequestMatcher(MediaType.TEXT_HTML)
          )
      }
      // Accept access tokens for User Info and/or Client Registration
      .oauth2ResourceServer { oauth2ResourceServer ->
        oauth2ResourceServer
          .jwt(Customizer.withDefaults())
      }

    return http.build()
  }

  // @formatter:off
  @Bean
  fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository {
    val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("messaging-client")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
      .redirectUri("http://127.0.0.1:8080/authorized")
      .postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .scope("message.read")
      .scope("message.write")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .build()

    val deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("device-messaging-client")
      .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
      .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .scope("message.read")
      .scope("message.write")
      .build()

    // Save registered client's in db as if in-memory
    val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
    registeredClientRepository.save(registeredClient)
    registeredClientRepository.save(deviceClient)
    return registeredClientRepository
  }
  // @formatter:on

  @Bean
  fun authorizationService(
    jdbcTemplate: JdbcTemplate?,
    registeredClientRepository: RegisteredClientRepository?
  ): JdbcOAuth2AuthorizationService {
    return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun authorizationConsentService(
    jdbcTemplate: JdbcTemplate?,
    registeredClientRepository: RegisteredClientRepository?
  ): JdbcOAuth2AuthorizationConsentService {
    // Will be used by the ConsentController
    return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun idTokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext?> {
    return FederatedIdentityIdTokenCustomizer()
  }

  @Bean
  fun jwkSource(): JWKSource<SecurityContext> {
    val rsaKey: RSAKey = Jwks.generateRsa()
    val jwkSet = JWKSet(rsaKey)
    return JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? ->
      jwkSelector.select(
        jwkSet
      )
    }
  }

  @Bean
  fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
  }

  @Bean
  fun authorizationServerSettings(): AuthorizationServerSettings {
    // This is also accessible via: AuthorizationServerContextHolder.getContext().authorizationServerSettings
    return AuthorizationServerSettings.builder().build()
  }

  @Bean
  fun embeddedDatabase(): EmbeddedDatabase {
    // @formatter:off
    return EmbeddedDatabaseBuilder()
      .generateUniqueName(true)
      .setType(EmbeddedDatabaseType.H2)
      .setScriptEncoding("UTF-8")
      .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
      .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
      .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
      .build()
    // @formatter:on
  }

  companion object {
    val CUSTOM_CONSENT_PAGE_URI: String = "/oauth2/consent"

    private fun generateRsaKey(): KeyPair {
      val keyPair: KeyPair
      try {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        keyPair = keyPairGenerator.generateKeyPair()
      } catch (ex: Exception) {
        throw IllegalStateException(ex)
      }
      return keyPair
    }
  }
}