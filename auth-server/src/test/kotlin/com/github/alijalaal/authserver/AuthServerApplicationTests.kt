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
package com.github.alijalaal.authserver

import com.gargoylesoftware.htmlunit.Page
import com.gargoylesoftware.htmlunit.WebClient
import com.gargoylesoftware.htmlunit.WebResponse
import com.gargoylesoftware.htmlunit.html.HtmlButton
import com.gargoylesoftware.htmlunit.html.HtmlElement
import com.gargoylesoftware.htmlunit.html.HtmlInput
import com.gargoylesoftware.htmlunit.html.HtmlPage
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.HttpStatus
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.web.util.UriComponentsBuilder
import java.io.IOException

/**
 * Integration tests for the sample Authorization Server.
 *
 * @author Daniel Garnier-Moiroux
 * @author Ali Jalal
 */
@ExtendWith(SpringExtension::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthServerApplicationTests {
  @Autowired
  private lateinit var webClient: WebClient

  @BeforeEach
  fun setUp() {
    webClient.options.isThrowExceptionOnFailingStatusCode = true
    webClient.options.isRedirectEnabled = true
    webClient.cookieManager.clearCookies() // log out
  }

  @Test
  @Throws(IOException::class)
  fun whenLoginSuccessfulThenDisplayBadRequestError() {
    val page: HtmlPage = webClient.getPage("/")

    assertLoginPage(page)

    webClient.options.isThrowExceptionOnFailingStatusCode = false
    val signInResponse: WebResponse = signIn<Page>(page, "user1", "password").getWebResponse()

    assertThat(signInResponse.statusCode).isEqualTo(HttpStatus.OK.value()) // index page
  }

  @Test
  @Throws(IOException::class)
  fun whenLoginFailsThenDisplayBadCredentials() {
    val page: HtmlPage = webClient.getPage("/")

    val loginErrorPage: HtmlPage = signIn(page, "user1", "wrong-password")

    val alert: HtmlElement = loginErrorPage.querySelector("div[role=\"alert\"]")
    assertThat(alert).isNotNull()
    assertThat(alert.asNormalizedText()).isEqualTo("Invalid username or password.")
  }

  @Test
  @Throws(IOException::class)
  fun whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() {
    val page: HtmlPage = webClient.getPage(AUTHORIZATION_REQUEST)

    assertLoginPage(page)
  }

  @Test
  @Throws(IOException::class)
  fun whenLoggingInAndRequestingTokenThenRedirectsToClientApplication() {
    // Log in
    webClient.options.isThrowExceptionOnFailingStatusCode = false
    webClient.options.isRedirectEnabled = false
    signIn<Page>(webClient.getPage("/login"), "user1", "password")

    // Request token
    val response: WebResponse =
      webClient.getPage<Page>(AUTHORIZATION_REQUEST).webResponse

    assertThat(response.statusCode).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value())
    val location: String = response.getResponseHeaderValue("location")
    assertThat(location).startsWith(REDIRECT_URI)
    assertThat(location).contains("code=")
  }

  companion object {
    private const val REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc"

    private val AUTHORIZATION_REQUEST = UriComponentsBuilder
      .fromPath("/oauth2/authorize")
      .queryParam("response_type", "code")
      .queryParam("client_id", "messaging-client")
      .queryParam("scope", "openid")
      .queryParam("state", "some-state")
      .queryParam("redirect_uri", REDIRECT_URI)
      .toUriString()

    @Throws(IOException::class)
    private fun <P : Page?> signIn(page: HtmlPage, username: String, password: String): P {
      val usernameInput: HtmlInput = page.querySelector("input[name=\"username\"]")
      val passwordInput: HtmlInput = page.querySelector("input[name=\"password\"]")
      val signInButton: HtmlButton = page.querySelector("button")

      usernameInput.type(username)
      passwordInput.type(password)
      return signInButton.click()
    }

    private fun assertLoginPage(page: HtmlPage) {
      assertThat(page.url.toString()).endsWith("/login")

      val usernameInput: HtmlInput = page.querySelector("input[name=\"username\"]")
      val passwordInput: HtmlInput = page.querySelector("input[name=\"password\"]")
      val signInButton: HtmlButton = page.querySelector("button")

      assertThat(usernameInput).isNotNull()
      assertThat(passwordInput).isNotNull()
      assertThat(signInButton.textContent).isEqualTo("Sign in")
    }
  }
}
