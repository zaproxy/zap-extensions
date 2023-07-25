plugins {
    `kotlin-dsl`
    id("com.diffplug.spotless") version "6.20.0"
}

repositories {
    mavenCentral()
}

spotless {
    java {
        licenseHeaderFile(file("../gradle/spotless/license.java"))
        googleJavaFormat("1.17.0").aosp()
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
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.20.0")
}

java {
    val javaVersion = JavaVersion.VERSION_11
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

kotlin {
    jvmToolchain(11)
}
