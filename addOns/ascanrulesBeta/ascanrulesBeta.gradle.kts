import org.zaproxy.gradle.addon.AddOnStatus

version = "27"
description = "The beta quality Active Scanner rules"

zapAddOn {
    addOnName.set("Active scanner rules (beta)")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.7.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    implementation("com.googlecode.java-diff-utils:diffutils:1.2.1")

    testImplementation(project(":testutils"))
    testImplementation("org.apache.commons:commons-lang3:3.5")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/IntegerOverflow.java"))
}
