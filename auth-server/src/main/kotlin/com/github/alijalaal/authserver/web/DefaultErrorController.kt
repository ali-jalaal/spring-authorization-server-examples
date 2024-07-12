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
package com.github.alijalaal.authserver.web

import jakarta.servlet.RequestDispatcher
import jakarta.servlet.http.HttpServletRequest
import org.springframework.boot.web.servlet.error.ErrorController
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.StringUtils
import org.springframework.web.bind.annotation.RequestMapping

/**
 * @author Steve Riesenberg
 * @author Ali Jalal
 * @since 1.1
 */
@Controller
class DefaultErrorController : ErrorController {
  @RequestMapping("/error")
  fun handleError(model: Model, request: HttpServletRequest): String {
    val errorMessage = getErrorMessage(request)
    if (errorMessage.startsWith("[access_denied]")) {
      model.addAttribute("errorTitle", "Access Denied")
      model.addAttribute("errorMessage", "You have denied access.")
    } else {
      model.addAttribute("errorTitle", "Error")
      model.addAttribute("errorMessage", errorMessage)
    }
    return "error"
  }

  private fun getErrorMessage(request: HttpServletRequest): String {
    val errorMessage = request.getAttribute(RequestDispatcher.ERROR_MESSAGE) as String
    return if (StringUtils.hasText(errorMessage)) errorMessage else ""
  }
}
