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
package com.github.alijalaal.client.authorization

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.client.*
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.util.Assert
import java.time.Clock
import java.time.Duration
import java.util.*
import java.util.function.Function

/**
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
class DeviceCodeOAuth2AuthorizedClientProvider : OAuth2AuthorizedClientProvider {
  private var accessTokenResponseClient: OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> =
    OAuth2DeviceAccessTokenResponseClient()

  private var clockSkew: Duration = Duration.ofSeconds(60)

  private var clock: Clock = Clock.systemUTC()

  fun setAccessTokenResponseClient(accessTokenResponseClient: OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest>) {
    this.accessTokenResponseClient = accessTokenResponseClient
  }

  fun setClockSkew(clockSkew: Duration) {
    this.clockSkew = clockSkew
  }

  fun setClock(clock: Clock) {
    this.clock = clock
  }

  override fun authorize(context: OAuth2AuthorizationContext): OAuth2AuthorizedClient? {
    Assert.notNull(context, "context cannot be null")
    val clientRegistration = context.clientRegistration
    if (AuthorizationGrantType.DEVICE_CODE != clientRegistration.authorizationGrantType) {
      return null
    }
    val authorizedClient = context.authorizedClient
    if (authorizedClient != null && !hasTokenExpired(authorizedClient.accessToken)) {
      // If client is already authorized but access token is NOT expired than no
      // need for re-authorization
      return null
    }
    if (authorizedClient != null && authorizedClient.refreshToken != null) {
      // If client is already authorized but access token is expired and a
      // refresh token is available, delegate to refresh_token.
      return null
    }
    // *****************************************************************
    // Get device_code set via DefaultOAuth2AuthorizedClientManager#setContextAttributesMapper()
    // *****************************************************************
    val deviceCode = context.getAttribute<String>(OAuth2ParameterNames.DEVICE_CODE)
    // Attempt to authorize the client, which will repeatedly fail until the user grants authorization
    val deviceGrantRequest = OAuth2DeviceGrantRequest(clientRegistration, deviceCode)
    val tokenResponse = getTokenResponse(clientRegistration, deviceGrantRequest)
    return OAuth2AuthorizedClient(
      clientRegistration, context.principal.name,
      tokenResponse.accessToken, tokenResponse.refreshToken
    )
  }

  private fun getTokenResponse(
    clientRegistration: ClientRegistration,
    deviceGrantRequest: OAuth2DeviceGrantRequest
  ): OAuth2AccessTokenResponse {
    try {
      return accessTokenResponseClient.getTokenResponse(deviceGrantRequest)
    } catch (ex: OAuth2AuthorizationException) {
      throw ClientAuthorizationException(ex.error, clientRegistration.registrationId, ex)
    }
  }

  private fun hasTokenExpired(token: OAuth2Token): Boolean {
    return clock.instant().isAfter(token.expiresAt!!.minus(this.clockSkew))
  }

  companion object {
    fun deviceCodeContextAttributesMapper(): Function<OAuth2AuthorizeRequest, Map<String?, Any>> {
      return Function { authorizeRequest: OAuth2AuthorizeRequest ->
        val request =
          authorizeRequest.getAttribute<HttpServletRequest>(HttpServletRequest::class.java.name)
        Assert.notNull(request, "request cannot be null")

        // Obtain device code from request
        val deviceCode = request!!.getParameter(OAuth2ParameterNames.DEVICE_CODE)
        if ((deviceCode != null)) Collections.singletonMap<String?, Any>(
          OAuth2ParameterNames.DEVICE_CODE,
          deviceCode
        ) else emptyMap<String, Any>()
      }
    }
  }
}