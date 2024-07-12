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

import com.github.alijalaal.authserver.web.AuthorizationConsentController
import org.springframework.aot.hint.*
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.ImportRuntimeHints
import org.thymeleaf.expression.Lists
import java.util.*

/**
 * @author Joe Grandja
 * @author Josh Long
 * @author Ali Jalal
 * @since 1.1
 */
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
