plugins {
    `java-library`
}

description = "Common test utilities for the add-ons."

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val nanohttpdVersion = "2.3.1"
val jupiterVersion = "5.7.0"

dependencies {
    compileOnly("org.zaproxy:zap:2.9.0")

    api("org.hamcrest:hamcrest-library:1.3")
    api("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    api("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    runtimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")
    api("org.mockito:mockito-junit-jupiter:3.6.28")

    api("org.nanohttpd:nanohttpd-webserver:$nanohttpdVersion")
    api("org.nanohttpd:nanohttpd-websocket:$nanohttpdVersion")
}
