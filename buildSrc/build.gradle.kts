plugins {
    `kotlin-dsl`
    id("com.diffplug.spotless") version "6.20.0"
    id("org.zaproxy.common") version "0.2.0"
}

repositories {
    mavenCentral()
}

spotless {
    kotlin {
        ktlint()
    }

    kotlinGradle {
        ktlint()
    }
}

dependencies {
    implementation("commons-codec:commons-codec:1.15")
    implementation("io.github.bonigarcia:webdrivermanager:5.7.0") {
        exclude("com.fasterxml.jackson.core")
    }
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.20.0")
}
