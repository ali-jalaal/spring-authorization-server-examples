plugins {
  kotlin("jvm") version "1.9.24"
  kotlin("plugin.spring") version "1.9.24"
  id("org.springframework.boot") version "3.3.1"
  id("io.spring.dependency-management") version "1.1.5"
}

repositories {
  mavenCentral()
}

subprojects {
  apply(plugin = "org.jetbrains.kotlin.jvm")
  apply(plugin = "org.springframework.boot")

  group = "com.github.alijalaal.spring-authorization-server-examples"
  version = "0.0.1-SNAPSHOT"

  repositories {
    mavenCentral()
  }

  java {
    toolchain {
      languageVersion = JavaLanguageVersion.of(17)
    }
  }

  kotlin {
    compilerOptions {
      freeCompilerArgs.addAll("-Xjsr305=strict")
    }
  }

  tasks.withType<Test> {
    useJUnitPlatform()
  }

  tasks.register("bootRunLocal") {
    group = "application"
    doFirst {
      tasks.bootRun.configure {
        systemProperty("spring.profiles.active", "local")
      }
    }
    finalizedBy("bootRun")
  }
}
