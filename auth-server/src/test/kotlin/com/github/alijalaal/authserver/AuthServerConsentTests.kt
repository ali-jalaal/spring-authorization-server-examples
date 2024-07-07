package com.github.alijalaal.authserver


import com.gargoylesoftware.htmlunit.Page
import com.gargoylesoftware.htmlunit.WebClient
import com.gargoylesoftware.htmlunit.WebResponse
import com.gargoylesoftware.htmlunit.html.DomElement
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput
import com.gargoylesoftware.htmlunit.html.HtmlPage
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.web.util.UriComponentsBuilder
import java.io.IOException
import java.util.function.Consumer

import org.assertj.core.api.Assertions.assertThat

/**
 * Consent screen integration tests for the sample Authorization Server.
 *
 * @author Dmitriy Dubson
 */
@ExtendWith(SpringExtension::class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthServerConsentTests {
  @Autowired
  private val webClient: WebClient? = null

  @MockBean
  private val authorizationConsentService: OAuth2AuthorizationConsentService? = null

  private val redirectUri = "http://127.0.0.1/login/oauth2/code/messaging-client-oidc"

  private val authorizationRequestUri = UriComponentsBuilder
    .fromPath("/oauth2/authorize")
    .queryParam("response_type", "code")
    .queryParam("client_id", "messaging-client")
    .queryParam("scope", "openid message.read message.write")
    .queryParam("state", "state")
    .queryParam("redirect_uri", this.redirectUri)
    .toUriString()

  @BeforeEach
  fun setUp() {
    webClient!!.getOptions().setThrowExceptionOnFailingStatusCode(false)
    webClient!!.getOptions().setRedirectEnabled(true)
    webClient!!.getCookieManager().clearCookies()
    Mockito.`when`(authorizationConsentService!!.findById(ArgumentMatchers.any(), ArgumentMatchers.any()))
      .thenReturn(null)
  }

  @Test
  @WithMockUser("user1")
  @Throws(IOException::class)
  fun whenUserConsentsToAllScopesThenReturnAuthorizationCode() {
    val consentPage: HtmlPage = webClient!!.getPage(this.authorizationRequestUri)
    assertThat(consentPage.getTitleText()).isEqualTo("Custom consent page - Consent required")

    val scopes: MutableList<HtmlCheckBoxInput> = ArrayList<HtmlCheckBoxInput>()
    consentPage.querySelectorAll("input[name='scope']").forEach { scope -> scopes.add(scope as HtmlCheckBoxInput) }
    for (scope in scopes) {
      scope.click<Page>()
    }

    val scopeIds: MutableList<String> = ArrayList()
    scopes.forEach(Consumer<HtmlCheckBoxInput> { scope: HtmlCheckBoxInput ->
      assertThat(scope.isChecked()).isTrue()
      scopeIds.add(scope.getId())
    })
    Assertions.assertThat(scopeIds).containsExactlyInAnyOrder("message.read", "message.write")

    val submitConsentButton: DomElement = consentPage.querySelector("button[id='submit-consent']")
    webClient!!.getOptions().setRedirectEnabled(false)

    val approveConsentResponse: WebResponse = submitConsentButton.click<Page>().getWebResponse()
    assertThat(approveConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value())
    val location: String = approveConsentResponse.getResponseHeaderValue("location")
    Assertions.assertThat(location).startsWith(this.redirectUri)
    Assertions.assertThat(location).contains("code=")
  }

  @Test
  @WithMockUser("user1")
  @Throws(IOException::class)
  fun whenUserCancelsConsentThenReturnAccessDeniedError() {
    val consentPage: HtmlPage = webClient!!.getPage(this.authorizationRequestUri)
    assertThat(consentPage.getTitleText()).isEqualTo("Custom consent page - Consent required")

    val cancelConsentButton: DomElement = consentPage.querySelector("button[id='cancel-consent']")
    webClient!!.getOptions().setRedirectEnabled(false)

    val cancelConsentResponse: WebResponse = cancelConsentButton.click<Page>().getWebResponse()
    assertThat(cancelConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value())
    val location: String = cancelConsentResponse.getResponseHeaderValue("location")
    Assertions.assertThat(location).startsWith(this.redirectUri)
    Assertions.assertThat(location).contains("error=access_denied")
  }
}
