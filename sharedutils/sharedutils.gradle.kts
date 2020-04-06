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

    implementation("org.apache.commons:commons-csv:1.8")
    implementation("commons-io:commons-io:2.6")
    implementation("org.apache.commons:commons-collections4:4.4")

    testImplementation(project(":testutils"))
    testImplementation(zap)
}
