package com.github.alijalaal.client.federation

import org.springframework.security.oauth2.core.user.OAuth2User
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Consumer

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
