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

    implementation(project(":testutilscore"))
    implementation(project(":addOns:network"))
    implementation(libs.testutils.httpclient5)

    api(libs.testutils.nanohttpd.webserver)
    api(libs.testutils.nanohttpd.websocket)
}

tasks.withType<Test>().configureEach {
    systemProperties.putAll(
        mapOf(
            "wdm.chromeDriverVersion" to "108.0.5359.71",
            "wdm.geckoDriverVersion" to "0.36.0",
            "wdm.forceCache" to "true",
        ),
    )
}
