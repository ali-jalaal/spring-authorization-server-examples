package com.github.alijalaal.client.authorization

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.util.Assert

class OAuth2DeviceGrantRequest(clientRegistration: ClientRegistration?, deviceCode: String?) :
  AbstractOAuth2AuthorizationGrantRequest(AuthorizationGrantType.DEVICE_CODE, clientRegistration) {
  val deviceCode: String?

  init {
    Assert.hasText(deviceCode, "deviceCode cannot be empty")
    this.deviceCode = deviceCode
  }
}
