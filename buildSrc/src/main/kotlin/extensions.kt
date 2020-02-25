import com.diffplug.gradle.spotless.FormatExtension
import com.diffplug.gradle.spotless.GradleProvisioner
import com.diffplug.gradle.spotless.SpotlessExtension
import com.diffplug.spotless.java.GoogleJavaFormatStep
import org.gradle.api.Project

/**
 * Configures the java extension with all Java files except the given ones and configures
 * a format extension with Google Java Format (AOSP) step for the given files.
 */
fun SpotlessExtension.javaWith3rdPartyFormatted(project: Project, files: List<String>) {
    java({
        target(project.fileTree(project.projectDir) {
            include("**/*.java")
            exclude(files)
        })
    })
    format3rdParty(project, files)
}

/**
 * Adds a custom format for the given files with Google Java Format (AOSP) step.
 */
fun SpotlessExtension.format3rdParty(project: Project, files: List<String>): Unit =
    this.format("3rdParty", {
        target(project.fileTree(project.projectDir) {
            include(files)
        })

        googleJavaFormatAosp(project)
    })

/**
 * Adds the Google Java Format (AOSP) step to the format extension.
 */
fun FormatExtension.googleJavaFormatAosp(project: Project): Unit =
    this.addStep(GoogleJavaFormatStep.create(
            GoogleJavaFormatStep.defaultVersion(),
            "AOSP",
            GradleProvisioner.fromProject(project)
    ))