import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

description = "Request numbered panel."

zapAddOn {
    addOnName.set("Requester")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("Surikato and the ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/requester/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

spotless {
    format("help-html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(fileTree(projectDir) {
            include("src/**/help/**/*.html")
        })
    })
}

dependencies {
    testImplementation(project(":testutils"))
}
