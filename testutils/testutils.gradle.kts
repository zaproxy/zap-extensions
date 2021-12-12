plugins {
    `java-library`
}

description = "Common test utilities for the add-ons."

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val nanohttpdVersion = "2.3.1"
val jupiterVersion = "5.8.1"

configurations {
    "compileClasspath" {
        exclude(group = "log4j")
        exclude(group = "org.apache.logging.log4j", module = "log4j-1.2-api")
    }
}

dependencies {
    compileOnly("org.zaproxy:zap:2.11.1")

    api("org.hamcrest:hamcrest-library:2.2")
    api("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    api("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    runtimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")
    api("org.mockito:mockito-junit-jupiter:4.0.0")

    api("org.nanohttpd:nanohttpd-webserver:$nanohttpdVersion")
    api("org.nanohttpd:nanohttpd-websocket:$nanohttpdVersion")
}
