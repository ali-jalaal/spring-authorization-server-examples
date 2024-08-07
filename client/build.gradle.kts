plugins {
  id("org.springframework.boot")
  id("io.spring.dependency-management")
  kotlin("jvm")
  kotlin("plugin.spring")
}

ext {
  set("mainClassName", "com.github.alijalaal.client.ClientApplicationKt")
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
  implementation("org.springframework:spring-webflux")
  implementation("io.projectreactor.netty:reactor-netty")
  implementation("org.webjars:webjars-locator-core")
  implementation("org.webjars:bootstrap:5.2.3")
  implementation("org.webjars:popper.js:2.9.3")
  implementation("org.webjars:jquery:3.6.4")

  compileOnly("org.springframework.boot:spring-boot-devtools")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.jetbrains.kotlin:kotlin-reflect")
  testImplementation("org.springframework.boot:spring-boot-starter-test")
  testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
