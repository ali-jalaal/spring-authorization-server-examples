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
package com.github.alijalaal.authserver.jose

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.SecretKey

/**
 * @author Joe Grandja
 * @author Ali Jalal
 * @since 1.1
 */
object Jwks {
  fun generateRsa(): RSAKey {
    val keyPair: KeyPair = KeyGeneratorUtils.generateRsaKey()
    val publicKey = keyPair.public as RSAPublicKey
    val privateKey = keyPair.private as RSAPrivateKey
    // @formatter:off
    return RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build()
    // @formatter:on
  }

  fun generateEc(): ECKey {
    val keyPair: KeyPair = KeyGeneratorUtils.generateEcKey()
    val publicKey = keyPair.public as ECPublicKey
    val privateKey = keyPair.private as ECPrivateKey
    val curve = Curve.forECParameterSpec(publicKey.params)
    // @formatter:off
    return ECKey.Builder(curve, publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build()
    // @formatter:on
  }

  fun generateSecret(): OctetSequenceKey {
    val secretKey: SecretKey = KeyGeneratorUtils.generateSecretKey()
    // @formatter:off
    return OctetSequenceKey.Builder(secretKey)
      .keyID(UUID.randomUUID().toString())
      .build()
    // @formatter:on
  }
}
