import org.springframework.boot.gradle.tasks.run.BootRun

plugins {
  kotlin("jvm") version "1.9.24"
  kotlin("plugin.spring") version "1.9.24"
  id("org.springframework.boot") version "3.3.1"
  id("io.spring.dependency-management") version "1.1.5"
  id("com.avast.gradle.docker-compose") version "0.17.7"
}

ext {
  set("mainClassName", "")
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

  tasks.getByName<Jar>("jar") { // Disable plain jar (only generate fat jar)
    enabled = false
  }

  kotlin {
    compilerOptions {
      freeCompilerArgs.addAll("-Xjsr305=strict")
    }
  }

  tasks.withType<Test> {
    useJUnitPlatform()
  }

  tasks.register("bootLocalRun", BootRun::class) {
    group = "custom"
    description = "Runs this project as a Spring Boot application using application-local.yaml."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set(ext["mainClassName"].toString())
    systemProperty("spring.profiles.active", "local")
  }
}

dockerCompose {
  useComposeFiles.add("compose.yaml")
  forceRecreate = true
  stopContainers = true
  captureContainersOutput = true
}

task("assembleAll") {
  group = "custom"
  description = "Assemble all subprojects."
  dependsOn(subprojects.map { it.tasks.assemble })
}

task("cleanAll") {
  group = "custom"
  description = "Clean all subprojects."
  dependsOn(subprojects.map { it.tasks.clean })
}
