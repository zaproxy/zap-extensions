import org.zaproxy.gradle.addon.AddOnStatus

description = "Displays a dialog showing the differences between 2 requests or responses. It uses diffutils and diff_match_patch"

zapAddOn {
    addOnName.set("Diff")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/diff/")
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.23.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("commonlib")
    implementation("com.googlecode.java-diff-utils:diffutils:1.3.0")
}

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                // Ignore 3rd-party code.
                exclude("src/**/diff_match_patch.java", "src/**/ZapDiffRowGenerator.java")
            },
        )
    }
}
