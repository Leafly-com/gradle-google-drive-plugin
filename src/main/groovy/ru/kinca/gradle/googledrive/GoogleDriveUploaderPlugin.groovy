package ru.kinca.gradle.googledrive

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * A plugin that compresses specified files to an archive and uploads it to
 * Google Drive.
 *
 * @author Valentin Naumov
 */
class GoogleDriveUploaderPlugin
implements Plugin<Project>
{
    protected static final String EXTENSION_NAME = 'googleDrive'
    protected static final String DEFAULT_TASK_NAME = 'uploadToDrive'

    @SuppressWarnings(['UnnecessaryObjectReferences'])
    @Override
    void apply(
        Project project)
    {
        ConfigExtension config = project.extensions.create(EXTENSION_NAME, ConfigExtension, project)

        project.tasks.create(DEFAULT_TASK_NAME, UploadTask) { UploadTask it ->
            it.clientIdProvider = config.clientIdProvider
            it.clientSecretProvider = config.clientSecretProvider
            it.destinationFolderPathProvider = config.destinationFolderPathProvider
            it.destinationFolderIdProvider = config.destinationFolderIdProvider
            it.destinationNamesProvider = config.destinationNamesProvider
            it.filesProvider = config.filesProvider
            it.permissionsProvider = config.permissionsProvider
            it.updateIfExistsProvider = config.updateIfExistsProvider
            it.credentialsDirProvider = config.credentialsDirProvider
            it.serviceAccountJsonProvider = config.serviceAccountJsonProvider
        }
    }

    /**
     * Splits string to path elements using slash as a separator.
     *
     * @param path
     *        folder names separated by slash.
     * @return list of path names.
     */
    static List<String> toPathElements(
        String path)
    {
        path.split('/') as List<String>
    }
}
