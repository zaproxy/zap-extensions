import org.zaproxy.gradle.addon.AddOnStatus

version = "9"
description = "Forced browsing of files and directories using code from the OWASP DirBuster tool"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Forced Browse")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Dev Team")
    }
}

dependencies {
    testImplementation(project(":testutils"))
    testImplementation("org.simpleframework:simple:5.0.2")
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/main/java/com/sittinglittleduck/**/*.java"))
}
