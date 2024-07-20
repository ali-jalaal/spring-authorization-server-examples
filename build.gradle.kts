import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.springframework.boot.gradle.tasks.run.BootRun

plugins {
  kotlin("jvm") version "2.0.0"
  kotlin("plugin.spring") version "2.0.0"
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

  dependencies {
    testImplementation(kotlin("test"))
  }

  kotlin {
    compilerOptions {
      languageVersion.set(KotlinVersion.KOTLIN_2_0)
      apiVersion.set(KotlinVersion.KOTLIN_2_0)
      jvmTarget.set(JvmTarget.JVM_17)
      freeCompilerArgs.addAll("-Xjsr305=strict")
    }
  }

  tasks.getByName<Jar>("jar") { // Disable plain jar (only generate fat jar)
    enabled = false
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
