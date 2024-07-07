package com.github.alijalaal.authserver

import com.github.alijalaal.authserver.web.AuthorizationConsentController
import org.springframework.aot.hint.MemberCategory
import org.springframework.aot.hint.RuntimeHints
import org.springframework.aot.hint.RuntimeHintsRegistrar
import org.springframework.aot.hint.TypeHint
import org.springframework.aot.hint.TypeReference
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ImportRuntimeHints
import org.thymeleaf.expression.Lists
import java.util.Arrays

@SpringBootApplication
@ImportRuntimeHints(AuthServerApplication.DemoAuthorizationServerApplicationRuntimeHintsRegistrar::class)
class AuthServerApplication {
  internal class DemoAuthorizationServerApplicationRuntimeHintsRegistrar : RuntimeHintsRegistrar {
    override fun registerHints(hints: RuntimeHints, classLoader: ClassLoader?) {
      // Thymeleaf
      hints.reflection().registerTypes(
        Arrays.asList<TypeReference>(
          TypeReference.of(AuthorizationConsentController.ScopeWithDescription::class.java),
          TypeReference.of(Lists::class.java)
        )
      ) { builder: TypeHint.Builder ->
        builder.withMembers(
          MemberCategory.DECLARED_FIELDS,
          MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
          MemberCategory.INVOKE_DECLARED_METHODS
        )
      }
    }
  }
}

fun main(args: Array<String>) {
  runApplication<AuthServerApplication>(*args)
}
