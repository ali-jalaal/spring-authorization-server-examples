package com.github.alijalaal.authserver.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class DeviceController {
  @GetMapping("/activate")
  fun activate(@RequestParam(value = "user_code", required = false) userCode: String?): String {
    if (userCode != null) {
      return "redirect:/oauth2/device_verification?user_code=$userCode"
    }
    return "device-activate"
  }

  @GetMapping("/activated")
  fun activated(): String {
    return "device-activated"
  }

  @GetMapping(value = ["/"], params = ["success"])
  fun success(): String {
    return "device-activated"
  }
}