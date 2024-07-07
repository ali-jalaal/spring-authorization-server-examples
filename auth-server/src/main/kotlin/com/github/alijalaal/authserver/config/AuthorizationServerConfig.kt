package com.github.alijalaal.authserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
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
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
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
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Configuration
@EnableWebSecurity
// @Import(OAuth2AuthorizationServerConfiguration::class) // Use this annotation for minimal OAuth2 configuration (authorizationServerSecurityFilterChain()')
class AuthorizationServerConfig {

  @Bean
  @Order(1)
  @Throws(Exception::class)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity, registeredClientRepository: RegisteredClientRepository,
                                             authorizationServerSettings: AuthorizationServerSettings): SecurityFilterChain {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

    http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)

    // @formatter:off
    http.getConfigurer<OAuth2AuthorizationServerConfigurer>(OAuth2AuthorizationServerConfigurer::class.java)
/*
      .deviceAuthorizationEndpoint{deviceAuthorizationEndpoint:OAuth2DeviceAuthorizationEndpointConfigurer -> deviceAuthorizationEndpoint.verificationUri("/activate")}
      .deviceVerificationEndpoint{deviceVerificationEndpoint:OAuth2DeviceVerificationEndpointConfigurer -> deviceVerificationEndpoint.consentPage(AuthorizationServerConfig.CUSTOM_CONSENT_PAGE_URI)}
      .clientAuthentication{clientAuthentication:OAuth2ClientAuthenticationConfigurer -> clientAuthentication
        .authenticationConverter(deviceClientAuthenticationConverter)
        .authenticationProvider(deviceClientAuthenticationProvider)}
      .authorizationEndpoint{authorizationEndpoint:OAuth2AuthorizationEndpointConfigurer -> authorizationEndpoint.consentPage(AuthorizationServerConfig.CUSTOM_CONSENT_PAGE_URI)}
*/
      .oidc(Customizer.withDefaults<OidcConfigurer>()) // Enable OpenID Connect 1.0


    // Redirect to the login page when not authenticated from the authorization endpoint
    http
      .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
        exceptions
          .defaultAuthenticationEntryPointFor(
            LoginUrlAuthenticationEntryPoint("/login"),
            MediaTypeRequestMatcher(MediaType.TEXT_HTML)
          )
      }
      // Accept access tokens for User Info and/or Client Registration
      .oauth2ResourceServer { resourceServer: OAuth2ResourceServerConfigurer<HttpSecurity?> ->
        resourceServer
          .jwt(Customizer.withDefaults())
      }

    return http.build()
  }

/*
  @Bean
  fun webSecurityCustomizer(): WebSecurityCustomizer {
    return WebSecurityCustomizer { web -> web.ignoring().requestMatchers("/error") }
  }
*/

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
  fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository {
//    val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//      .clientId("oidc-client")
//      .clientSecret("{noop}secret")
//      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//      .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//      .postLogoutRedirectUri("http://127.0.0.1:8080/")
//      .scope(OidcScopes.OPENID)
//      .scope(OidcScopes.PROFILE)
//      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//      .build()
//
//    return InMemoryRegisteredClientRepository(oidcClient)

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

//    val deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
//      .clientId("device-messaging-client")
//      .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//      .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
//      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//      .scope("message.read")
//      .scope("message.write")
//      .build()

    // Save registered client's in db as if in-memory
    val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
    registeredClientRepository.save(registeredClient)
//    registeredClientRepository.save(deviceClient)
    return registeredClientRepository
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

  @Bean
  fun jwkSource(): JWKSource<SecurityContext> {
    val keyPair: KeyPair = generateRsaKey()
    val publicKey = keyPair.public as RSAPublicKey
    val privateKey = keyPair.private as RSAPrivateKey
    val rsaKey = RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build()
    val jwkSet = JWKSet(rsaKey)
    return ImmutableJWKSet(jwkSet)
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