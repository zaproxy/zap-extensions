plugins {
    `kotlin-dsl`
    id("com.diffplug.spotless") version "6.25.0"
    id("org.zaproxy.common") version "0.5.0"
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
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.25.0")
}
