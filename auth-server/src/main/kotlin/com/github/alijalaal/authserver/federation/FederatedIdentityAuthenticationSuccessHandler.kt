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
package com.github.alijalaal.authserver.federation

// tag::imports[]
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import java.io.IOException
import java.util.function.Consumer
// end::imports[]

/**
 * An {@link AuthenticationSuccessHandler} for capturing the {@link OidcUser} or
 * {@link OAuth2User} for Federated Account Linking or JIT Account Provisioning.
 *
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
// tag::class[]
class FederatedIdentityAuthenticationSuccessHandler : AuthenticationSuccessHandler {
  private val delegate: AuthenticationSuccessHandler = SavedRequestAwareAuthenticationSuccessHandler()

  private var oauth2UserHandler =
    Consumer { user: OAuth2User? -> }

  private var oidcUserHandler =
    Consumer { user: OidcUser -> oauth2UserHandler.accept(user) }

  @Throws(IOException::class, ServletException::class)
  override fun onAuthenticationSuccess(
    request: HttpServletRequest,
    response: HttpServletResponse,
    authentication: Authentication
  ) {
    if (authentication is OAuth2AuthenticationToken) {
      if (authentication.principal is OidcUser) {
        oidcUserHandler.accept(authentication.principal as OidcUser)
      } else if (authentication.principal is OAuth2User) {
        oauth2UserHandler.accept(authentication.principal as OAuth2User)
      }
    }

    delegate.onAuthenticationSuccess(request, response, authentication)
  }

  fun setOAuth2UserHandler(oauth2UserHandler: Consumer<OAuth2User?>) {
    this.oauth2UserHandler = oauth2UserHandler
  }

  fun setOidcUserHandler(oidcUserHandler: Consumer<OidcUser>) {
    this.oidcUserHandler = oidcUserHandler
  }
}
// end::class[]
