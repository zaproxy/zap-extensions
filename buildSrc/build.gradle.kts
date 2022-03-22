plugins {
    `kotlin-dsl`
    id("com.diffplug.spotless") version "5.14.2"
}

repositories {
    mavenCentral()
}

spotless {
    java {
        licenseHeaderFile(file("../gradle/spotless/license.java"))
        googleJavaFormat("1.7").aosp()
    }

    kotlin {
        ktlint()
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
    implementation("commons-codec:commons-codec:1.15")
    implementation("io.github.bonigarcia:webdrivermanager:5.1.0") {
        exclude("com.fasterxml.jackson.core")
    }
    implementation("com.diffplug.spotless:spotless-plugin-gradle:5.14.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}
