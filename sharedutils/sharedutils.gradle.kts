plugins {
    `java-library`
}

description = "Common utilities for the add-ons."

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    val zap = "org.zaproxy:zap:2.7.0"
    compileOnly(zap)

    testImplementation(project(":testutils"))
    testImplementation(zap)
}