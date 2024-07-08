package com.github.alijalaal.client.jose

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID
import javax.crypto.SecretKey


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
