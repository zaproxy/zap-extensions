description = "Bug Tracker extension."

zapAddOn {
    addOnName.set("Bug Tracker")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/bug-tracker/")
    }
}

dependencies {
    compileOnly(libs.bugtracker.bridgeMethodAnnotations) {
        exclude(group = "org.jenkins-ci")
    }
    compileOnly("com.github.spotbugs:spotbugs-annotations:4.9.6")
    implementation(libs.bugtracker.j2bugzilla) {
        // Not needed.
        exclude(group = "junit")
    }
    implementation(libs.bugtracker.githubApi) {
        // Not needed.
        exclude(group = "com.infradna.tool")
        // Provided by ZAP.
        exclude(group = "commons-codec")
        // Provided by ZAP.
        exclude(group = "commons-io")
    }
}
