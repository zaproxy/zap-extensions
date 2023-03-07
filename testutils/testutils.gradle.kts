plugins {
    `java-library`
}

description = "Common test utilities for the add-ons."

val nanohttpdVersion = "2.3.1"
val jupiterVersion = "5.9.2"

configurations {
    "compileClasspath" {
        exclude(group = "log4j")
        exclude(group = "org.apache.logging.log4j", module = "log4j-1.2-api")
    }
}

dependencies {
    compileOnly("org.zaproxy:zap:2.12.0")
    implementation(parent!!.childProjects.get("addOns")!!.childProjects.get("network")!!)
    implementation("org.apache.httpcomponents.client5:httpclient5:5.2-beta1")

    api("org.hamcrest:hamcrest-library:2.2")
    api("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    api("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    runtimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")
    api("org.mockito:mockito-junit-jupiter:5.1.1")

    api("org.nanohttpd:nanohttpd-webserver:$nanohttpdVersion")
    api("org.nanohttpd:nanohttpd-websocket:$nanohttpdVersion")
}
