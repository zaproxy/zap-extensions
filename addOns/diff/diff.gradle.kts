import org.zaproxy.gradle.addon.AddOnStatus

version = "10"
description = "Displays a dialog showing the differences between 2 requests or responses. It uses diffutils and diff_match_patch"

zapAddOn {
    addOnName.set("Diff")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.googlecode.java-diff-utils:diffutils:1.2.1")
}

spotless {
    java {
        target(fileTree(projectDir) {
            include("**/*.java")
            // Ignore 3rd-party code.
            exclude("**/diff_match_patch.java", "**/ZapDiffRowGenerator.java")
        })
    }
}
