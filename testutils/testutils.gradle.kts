plugins {
    `java-library`
}

description = "Common test utilities for the add-ons."

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val nanohttpdVersion = "2.3.1"

dependencies {
    compileOnly("org.zaproxy:zap:2.9.0")

    api("junit:junit:4.11")

    api("org.hamcrest:hamcrest-library:1.3")
    api("org.mockito:mockito-core:3.1.0")

    api("org.nanohttpd:nanohttpd-webserver:$nanohttpdVersion")
    api("org.nanohttpd:nanohttpd-websocket:$nanohttpdVersion")
}