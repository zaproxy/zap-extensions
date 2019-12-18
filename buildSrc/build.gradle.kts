plugins {
    `kotlin-dsl`
    id("com.diffplug.gradle.spotless") version "3.20.0"
}

repositories {
    mavenCentral()
}

spotless {
    java {
        licenseHeaderFile(file("../gradle/spotless/license.java"))
        googleJavaFormat().aosp()
    }

    kotlinGradle {
        ktlint()
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "utf-8"
    options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
}

dependencies {
    implementation("io.github.bonigarcia:webdrivermanager:3.7.1")
    implementation("com.diffplug.spotless:spotless-plugin-gradle:3.20.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}