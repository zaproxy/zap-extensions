import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows you to generate and analyze pseudo random tokens, such as those used for session handling or CSRF protection"

zapAddOn {
    addOnName.set("Token Generation and Analysis")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/token-generator/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                // 3rd-party code.
                exclude("src/**/com/fasteasytrade/**/*.java")
            },
        )
    }
}
