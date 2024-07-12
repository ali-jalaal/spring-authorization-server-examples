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
package com.github.alijalaal.authserver.authentication

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.util.Assert

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 * @see DeviceClientAuthenticationToken
 * @see DeviceClientAuthenticationConverter
 * @see OAuth2ClientAuthenticationFilter
 */
class DeviceClientAuthenticationProvider(registeredClientRepository: RegisteredClientRepository) :
  AuthenticationProvider {
  private val logger: Log = LogFactory.getLog(javaClass)
  private val registeredClientRepository: RegisteredClientRepository

  init {
    Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null")
    this.registeredClientRepository = registeredClientRepository
  }

  @Throws(AuthenticationException::class)
  override fun authenticate(authentication: Authentication): Authentication? {
    val deviceClientAuthentication =
      authentication as DeviceClientAuthenticationToken

    if (ClientAuthenticationMethod.NONE != deviceClientAuthentication.clientAuthenticationMethod) {
      return null
    }

    val clientId = deviceClientAuthentication.principal.toString()
    val registeredClient = registeredClientRepository.findByClientId(clientId)
    if (registeredClient == null) {
      throwInvalidClient(OAuth2ParameterNames.CLIENT_ID)
    }

    if (logger.isTraceEnabled) {
      logger.trace("Retrieved registered client")
    }

    if (!registeredClient!!.clientAuthenticationMethods.contains(
        deviceClientAuthentication.clientAuthenticationMethod
      )
    ) {
      throwInvalidClient("authentication_method")
    }

    if (logger.isTraceEnabled) {
      logger.trace("Validated device client authentication parameters")
    }

    if (logger.isTraceEnabled) {
      logger.trace("Authenticated device client")
    }

    return DeviceClientAuthenticationToken(
      registeredClient,
      deviceClientAuthentication.clientAuthenticationMethod, null
    )
  }

  override fun supports(authentication: Class<*>?): Boolean {
    return DeviceClientAuthenticationToken::class.java.isAssignableFrom(authentication)
  }

  companion object {
    private const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1"
    private fun throwInvalidClient(parameterName: String) {
      val error = OAuth2Error(
        OAuth2ErrorCodes.INVALID_CLIENT,
        "Device client authentication failed: $parameterName",
        ERROR_URI
      )
      throw OAuth2AuthenticationException(error)
    }
  }
}
