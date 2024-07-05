package com.github.alijalaal.client.web

import org.springframework.beans.factory.annotation.Value
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthorizationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.WebClient
import java.time.Instant
import java.util.*

@Controller
class DeviceController(
  private val clientRegistrationRepository: ClientRegistrationRepository, private val webClient: WebClient,
  @param:Value("\${messages.base-uri}") private val messagesBaseUri: String
) {
  @GetMapping("/device_authorize")
  fun authorize(model: Model): String {
    // @formatter:off
    val clientRegistration =
      clientRegistrationRepository.findByRegistrationId(
        "messaging-client-device-code")

    // @formatter:on
    val requestParameters: MultiValueMap<String, String> = LinkedMultiValueMap()
    requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId)
    requestParameters.add(
      OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(
        clientRegistration.scopes, " "
      )
    )

    val deviceAuthorizationUri =
      clientRegistration.providerDetails.configurationMetadata["device_authorization_endpoint"] as String?

    // @formatter:off
    val responseParameters =
      webClient.post()
        .uri(deviceAuthorizationUri!!)
        .headers{headers:HttpHeaders ->
          /*
                   * This sample demonstrates the use of a public client that does not
                   * store credentials or authenticate with the authorization server.
                   *
                   * See DeviceClientAuthenticationProvider in the authorization server
                   * sample for an example customization that allows public clients.
                   *
                   * For a confidential client, change the client-authentication-method to
                   * client_secret_basic and set the client-secret to send the
                   * OAuth 2.0 Device Authorization Request with a clientId/clientSecret.
                   */
          if (clientRegistration.clientAuthenticationMethod != ClientAuthenticationMethod.NONE) {
            headers.setBasicAuth(clientRegistration.clientId, clientRegistration.clientSecret)
          }
        }
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(requestParameters))
        .retrieve()
        .bodyToMono(TYPE_REFERENCE)
        .block()!!

    // @formatter:on
    Objects.requireNonNull(responseParameters, "Device Authorization Response cannot be null")
    val issuedAt = Instant.now()
    val expiresIn = responseParameters[OAuth2ParameterNames.EXPIRES_IN] as Int?
    val expiresAt = issuedAt.plusSeconds(expiresIn!!.toLong())

    model.addAttribute("deviceCode", responseParameters[OAuth2ParameterNames.DEVICE_CODE])
    model.addAttribute("expiresAt", expiresAt)
    model.addAttribute("userCode", responseParameters[OAuth2ParameterNames.USER_CODE])
    model.addAttribute("verificationUri", responseParameters[OAuth2ParameterNames.VERIFICATION_URI])
    // Note: You could use a QR-code to display this URL
    model.addAttribute(
      "verificationUriComplete",
      responseParameters[OAuth2ParameterNames.VERIFICATION_URI_COMPLETE]
    )

    return "device-authorize"
  }

  /**
   * @see .handleError
   */
  @PostMapping("/device_authorize")
  fun poll(
    @RequestParam(OAuth2ParameterNames.DEVICE_CODE) deviceCode: String?,
    @RegisteredOAuth2AuthorizedClient("messaging-client-device-code") authorizedClient: OAuth2AuthorizedClient?
  ): ResponseEntity<Void> {
    /*
           * The client will repeatedly poll until authorization is granted.
           *
           * The OAuth2AuthorizedClientManager uses the device_code parameter
           * to make a token request, which returns authorization_pending until
           * the user has granted authorization.
           *
           * If the user has denied authorization, access_denied is returned and
           * polling should stop.
           *
           * If the device code expires, expired_token is returned and polling
           * should stop.
           *
           * This endpoint simply returns 200 OK when the client is authorized.
           */

    return ResponseEntity.status(HttpStatus.OK).build()
  }

  @ExceptionHandler(OAuth2AuthorizationException::class)
  fun handleError(ex: OAuth2AuthorizationException): ResponseEntity<OAuth2Error> {
    val errorCode = ex.error.errorCode
    if (DEVICE_GRANT_ERRORS.contains(errorCode)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.error)
    }
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.error)
  }

  @GetMapping("/device_authorized")
  fun authorized(
    model: Model,
    @RegisteredOAuth2AuthorizedClient("messaging-client-device-code") authorizedClient: OAuth2AuthorizedClient?
  ): String {
    val messages = webClient.get()
      .uri(this.messagesBaseUri)
      .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
      .retrieve()
      .bodyToMono(Array<String>::class.java)
      .block()!!
    model.addAttribute("messages", messages)

    return "index"
  }

  companion object {
    private val DEVICE_GRANT_ERRORS: Set<String> = HashSet(
      mutableListOf(
        "authorization_pending",
        "slow_down",
        "access_denied",
        "expired_token"
      )
    )

    private val TYPE_REFERENCE: ParameterizedTypeReference<Map<String?, Any?>?> =
      object : ParameterizedTypeReference<Map<String?, Any?>?>() {}
  }
}
