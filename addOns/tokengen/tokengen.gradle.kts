import org.zaproxy.gradle.addon.AddOnStatus

version = "15"
description = "Allows you to generate and analyze pseudo random tokens, such as those used for session handling or CSRF protection"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Token Generation and Analysis")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/token-generator/")
        notBeforeVersion.set("2.10.0")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            // 3rd-party code.
            exclude("**/com/fasteasytrade/**/*.java")
        })
    }
}
