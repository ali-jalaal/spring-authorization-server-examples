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

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * @author Joe Grandja
 * @author Ali Jalal
 * @since 1.1
 */
internal object KeyGeneratorUtils {
  fun generateSecretKey(): SecretKey {
    val hmacKey: SecretKey
    try {
      hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey()
    } catch (ex: Exception) {
      throw IllegalStateException(ex)
    }
    return hmacKey
  }

  fun generateRsaKey(): KeyPair {
    val keyPair: KeyPair
    try {
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
      keyPairGenerator.initialize(2048)
      keyPair = keyPairGenerator.generateKeyPair()
    } catch (ex: Exception) {
      throw IllegalStateException(ex)
    }
    return keyPair
  }

  fun generateEcKey(): KeyPair {
    val ellipticCurve = EllipticCurve(
      ECFieldFp(
        BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")
      ),
      BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
      BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")
    )
    val ecPoint = ECPoint(
      BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
      BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
    )
    val ecParameterSpec = ECParameterSpec(
      ellipticCurve,
      ecPoint,
      BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
      1
    )

    val keyPair: KeyPair
    try {
      val keyPairGenerator = KeyPairGenerator.getInstance("EC")
      keyPairGenerator.initialize(ecParameterSpec)
      keyPair = keyPairGenerator.generateKeyPair()
    } catch (ex: Exception) {
      throw IllegalStateException(ex)
    }
    return keyPair
  }
}
