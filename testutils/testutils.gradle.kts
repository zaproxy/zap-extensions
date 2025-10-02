plugins {
    `java-library`
    id("org.zaproxy.common")
}

description = "Common test utilities for the add-ons."

configurations {
    "compileClasspath" {
        exclude(group = "log4j")
        exclude(group = "org.apache.logging.log4j", module = "log4j-1.2-api")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs = options.compilerArgs + "-Xlint:-processing"
}

dependencies {
    compileOnly(libs.testutils.zap)
    implementation(project(":addOns:network"))
    implementation(libs.testutils.httpclient5)

    api(libs.test.hamcrest)
    api(libs.test.junit.jupiter)
    runtimeOnly(libs.test.junit.platformLauncher)
    api(libs.test.mockito.junit.jupiter)

    api(libs.testutils.nanohttpd.webserver)
    api(libs.testutils.nanohttpd.websocket)
}
