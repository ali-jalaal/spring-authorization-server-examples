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
package com.github.alijalaal.authserver.federation

// tag::imports[]
import org.springframework.security.oauth2.core.user.OAuth2User
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Consumer

// end::imports[]

/**
 * Example {@link Consumer} to perform JIT provisioning of an {@link OAuth2User}.
 *
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
// tag::class[]
class UserRepositoryOAuth2UserHandler : Consumer<OAuth2User> {
  private val userRepository = UserRepository()

  override fun accept(user: OAuth2User) {
    // Capture user in a local data store on first authentication
    if (userRepository.findByName(user.name) == null) {
      println("Saving first-time user: name=" + user.name + ", claims=" + user.attributes + ", authorities=" + user.authorities)
      userRepository.save(user)
    }
  }

  internal class UserRepository {
    private val userCache: MutableMap<String, OAuth2User> = ConcurrentHashMap()

    fun findByName(name: String): OAuth2User? {
      return userCache[name]
    }

    fun save(oauth2User: OAuth2User) {
      userCache[oauth2User.name] = oauth2User
    }
  }
}
// end::class[]
