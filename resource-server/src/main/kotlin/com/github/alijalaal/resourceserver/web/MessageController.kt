package com.github.alijalaal.resourceserver.web

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class MessagesController {
  @get:GetMapping("/messages")
  val messages: Array<String>
    get() = arrayOf("Message 1", "Message 2", "Message 3")
}
