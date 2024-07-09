package com.github.alijalaal.authserver.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class LoginController {
  @GetMapping("/login")
  fun login(): String {
    return "login"
  }

  @GetMapping("/")
  fun index(): String {
    return "index"
  }
}
