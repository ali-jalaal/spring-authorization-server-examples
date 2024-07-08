package com.github.alijalaal.authserver.authentication

import org.springframework.lang.Nullable
import org.springframework.security.core.Transient
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient


@Transient
class DeviceClientAuthenticationToken : OAuth2ClientAuthenticationToken {
  constructor(
    clientId: String?, clientAuthenticationMethod: ClientAuthenticationMethod?,
    @Nullable credentials: Any?, @Nullable additionalParameters: Map<String?, Any?>?
  ) : super(clientId, clientAuthenticationMethod, credentials, additionalParameters)

  constructor(
    registeredClient: RegisteredClient?, clientAuthenticationMethod: ClientAuthenticationMethod?,
    @Nullable credentials: Any?
  ) : super(registeredClient, clientAuthenticationMethod, credentials)
}
