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

import org.springframework.http.HttpHeaders
import org.springframework.http.RequestEntity
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestOperations
import org.springframework.web.client.RestTemplate
import java.util.*

/**
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
class OAuth2DeviceAccessTokenResponseClient() : OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> {
  private var restOperations: RestOperations

  init {
    val restTemplate = RestTemplate(
      Arrays.asList(
        FormHttpMessageConverter(),
        OAuth2AccessTokenResponseHttpMessageConverter()
      )
    )
    restTemplate.errorHandler = OAuth2ErrorResponseErrorHandler()
    this.restOperations = restTemplate
  }

  fun setRestOperations(restOperations: RestOperations) {
    this.restOperations = restOperations
  }

  override fun getTokenResponse(deviceGrantRequest: OAuth2DeviceGrantRequest): OAuth2AccessTokenResponse {
    val clientRegistration: ClientRegistration = deviceGrantRequest.getClientRegistration()

    val headers = HttpHeaders()
    /*
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * See DeviceClientAuthenticationProvider in the authorization server
		 * sample for an example customization that allows public clients.
		 *
		 * For a confidential client, change the client-authentication-method
		 * to client_secret_basic and set the client-secret to send the
		 * OAuth 2.0 Token Request with a clientId/clientSecret.
		 */
    if (clientRegistration.clientAuthenticationMethod != ClientAuthenticationMethod.NONE) {
      headers.setBasicAuth(clientRegistration.clientId, clientRegistration.clientSecret)
    }

    val requestParameters: MultiValueMap<String, Any> = LinkedMultiValueMap()
    requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, deviceGrantRequest.getGrantType().getValue())
    requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId)
    requestParameters.add(OAuth2ParameterNames.DEVICE_CODE, deviceGrantRequest.deviceCode)

    // @formatter:off
    val requestEntity: RequestEntity<MultiValueMap<String, Any>> =
      RequestEntity.post(deviceGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
        .headers(headers)
        .body<MultiValueMap<String, Any>>(requestParameters)

    // @formatter:on
    try {
      return restOperations.exchange(
        requestEntity,
        OAuth2AccessTokenResponse::class.java
      ).body!!
    } catch (ex: RestClientException) {
      val oauth2Error = OAuth2Error(
        "invalid_token_response",
        "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
            + ex.message, null
      )
      throw OAuth2AuthorizationException(oauth2Error, ex)
    }
  }
}
