import org.zaproxy.gradle.addon.AddOnStatus

version = "14"
description = "Allows you to generate and analyze pseudo random tokens, such as those used for session handling or CSRF protection"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Token Generation and Analysis")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.6.0")

    manifest {
        author.set("ZAP Dev Team")
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
