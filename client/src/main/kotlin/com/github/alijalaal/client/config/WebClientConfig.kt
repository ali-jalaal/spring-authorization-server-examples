package com.github.alijalaal.client.config

import com.github.alijalaal.client.authorization.DeviceCodeOAuth2AuthorizedClientProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.web.reactive.function.client.WebClient

@Configuration
class WebClientConfig {
  @Bean
  fun webClient(authorizedClientManager: OAuth2AuthorizedClientManager?): WebClient {
    val oauth2Client = ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager)
    // @formatter:off
    return WebClient.builder()
      .apply(oauth2Client.oauth2Configuration())
      .build()
    // @formatter:on
  }

  @Bean
  fun authorizedClientManager(
    clientRegistrationRepository: ClientRegistrationRepository?,
    authorizedClientRepository: OAuth2AuthorizedClientRepository?
  ): OAuth2AuthorizedClientManager {
    // @formatter:off

    val authorizedClientProvider =
      OAuth2AuthorizedClientProviderBuilder.builder()
        .authorizationCode()
        .refreshToken()
        .clientCredentials()
        .provider(DeviceCodeOAuth2AuthorizedClientProvider())
        .build()

    // @formatter:on
    val authorizedClientManager = DefaultOAuth2AuthorizedClientManager(
      clientRegistrationRepository, authorizedClientRepository)
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider)

    // Set a contextAttributesMapper to obtain device_code from the request
    authorizedClientManager.setContextAttributesMapper(
      DeviceCodeOAuth2AuthorizedClientProvider.deviceCodeContextAttributesMapper())

    return authorizedClientManager
  }
}
