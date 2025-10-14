import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides database engines and related infrastructure."

val datanucleus by configurations.creating
configurations.api { extendsFrom(datanucleus) }

val flyway by configurations.creating
configurations.api { extendsFrom(flyway) }

val sqlite by configurations.creating
configurations.api { extendsFrom(sqlite) }

zapAddOn {
    addOnName.set("Database")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/database/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(datanucleus)
            libs.from(flyway)
            libs.from(sqlite)
        }
    }
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

spotless {
    format("help-html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(
            fileTree(projectDir) {
                include("src/**/help/**/*.html")
            },
        )
    })
}

dependencies {
    compileOnly(libs.log4j.core)

    datanucleus(libs.database.datanucleusJdo)
    sqlite(libs.database.sqliteJdbc)

    flyway(libs.database.flywayCore)
    flyway(libs.database.flywayDatabaseHsqldb)

    testImplementation(libs.log4j.core)
    testImplementation(project(":testutils"))
}
