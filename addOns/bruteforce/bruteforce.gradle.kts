import org.zaproxy.gradle.addon.AddOnStatus

version = "11"
description = "Forced browsing of files and directories using code from the OWASP DirBuster tool"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Forced Browse")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/forced-browse/")
        notBeforeVersion.set("2.10.0")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

spotless {
    javaWith3rdPartyFormatted(project, listOf("**/main/java/com/sittinglittleduck/**/*.java"))
}
