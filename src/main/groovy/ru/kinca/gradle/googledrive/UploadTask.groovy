package ru.kinca.gradle.googledrive

import com.google.api.client.googleapis.batch.BatchRequest
import com.google.api.client.http.FileContent
import com.google.api.client.util.store.FileDataStoreFactory
import com.google.api.services.drive.DriveRequest
import com.google.api.services.drive.model.File as DriveFile
import com.google.api.services.drive.model.Permission

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.TaskAction

/**
 * Task that uploads specified file to Google Drive. Opens a browser to
 * authorize, if was not authorized before.
 *
 * @author Valentin Naumov
 */
class UploadTask
extends DefaultTask
{
    protected static final List<Permission> DEFAULT_PERMISSIONS =
        [new Permission().setType('anyone').setRole('reader')]

    protected static final Boolean DEFAULT_UPDATE_IF_EXISTS = true

    private final Property<String> destinationFolderPathProperty

    private final Property<String> destinationFolderIdProperty

    private final Property<List<String>> destinationNamesProperty

    private final Property<List<File>> filesProperty

    private final Property<String> clientIdProperty

    private final Property<String> clientSecretProperty

    private final Property<List<Permission>> permissionsProperty

    private final Property<Boolean> updateIfExistsProperty

    private final Property<File> credentialsDirProperty

    private final Property<File> serviceAccountJsonProperty

    UploadTask()
    {
        destinationFolderPathProperty = project.objects.property(String)
        destinationFolderIdProperty = project.objects.property(String)
        destinationNamesProperty = project.objects.property(List)
        filesProperty = project.objects.property(List)
        clientIdProperty = project.objects.property(String)
        clientSecretProperty = project.objects.property(String)
        permissionsProperty = project.objects.property(List)

        // Wrapper type properties are assigned default values, we need to
        // override
        updateIfExistsProperty = project.objects.property(Boolean)
        updateIfExistsProperty.set(null as Boolean)

        credentialsDirProperty = project.objects.property(File)

        serviceAccountJsonProperty = project.objects.property(File)
    }

    @TaskAction
    void upload()
    {
        GoogleClient googleClient = new GoogleClient(
            clientId,
            clientSecret,
            new FileDataStoreFactory(credentialsDir),
            serviceAccountJson
        )

        String destinationFolderId = determineDestination(googleClient)

        files.eachWithIndex { file, idx ->
            if (!file.exists()) {
                return
            }

            String destinationName = (files.size() == destinationNames.size()) ? destinationNames.get(idx) : file.name
            DriveFile driveFile = new DriveFile()
            driveFile.setName(destinationName)
            driveFile.setParents([destinationFolderId])
            driveFile.setTeamDriveId("0AFdi6bicClgeUk9PVA")

            FileContent content = new FileContent('application/octet-stream', file)
            DriveRequest<DriveFile> modificationRequest

            List<DriveFile> existingDestinationFiles = DriveUtils.findInFolder(
                googleClient.drive, destinationFolderId, destinationName)
            if (existingDestinationFiles)
            {
                if (updateIfExists)
                {
                    // Update the most recent, if the are many with the same name
                    DriveFile updatedFile = existingDestinationFiles
                        .toSorted { it.getModifiedTime() }.first()

                    logger.info("File with name '${destinationName}' already" +
                        " exists, id: ${updatedFile.getId()}. Updating...")
                    modificationRequest = googleClient.drive.files().update(
                        updatedFile.getId(), null, content).setSupportsTeamDrives(true)
                }
                else
                {
                    throw new GradleException('Remote file(s) already exists,' +
                        " id: ${existingDestinationFiles*.getId()}")
                }
            }
            else
            {
                logger.info('Creating file...')
                modificationRequest = googleClient.drive.files()
                    .create(driveFile, content)
                    .setSupportsTeamDrives(true)
            }

            modificationRequest.getMediaHttpUploader().with {
                progressListener = {
                    logger.info('Uploaded: {} {}[bytes]({})',
                        it.uploadState,
                        String.format('%,3d', it.numBytesUploaded),
                        String.format('%2.1f%%', it.progress * 100))
                }
            }

            DriveFile updated = modificationRequest.execute()

//            logger.debug('Creating permissions...')
//            BatchRequest permissionsBatchRequest = googleClient.drive.batch()
//            permissions.each {
//                googleClient.drive.permissions().create(updated.getId(), it)
//                    .queue(permissionsBatchRequest, new SimpleJsonBatchCallBack(
//                    'Could not update permissions'))
//            }
//            permissionsBatchRequest.execute()

            logger.info("File '${file.canonicalPath}' is uploaded to" +
                " '$destinationFolderPath' and named '$destinationName'.")
            logger.quiet("Google Drive short link: ${getLink(updated)}")

        }
    }

    private String determineDestination(
        GoogleClient googleClient)
    {
        if (destinationFolderId && !destinationFolderPath)
        {
            return destinationFolderId
        }

        if (!destinationFolderId && destinationFolderPath)
        {
            return DriveUtils.makeDirs(
                googleClient.drive, 'root',
                GoogleDriveUploaderPlugin.toPathElements(destinationFolderPath))
        }

        return DriveUtils.makeDirs(
                googleClient.drive,
                destinationFolderId,
                GoogleDriveUploaderPlugin.toPathElements(destinationFolderPath)
        )
    }

    private static String getLink(
        DriveFile file)
    {
        "https://drive.google.com/open?id=${file.getId()}"
    }

    @Optional
    @Input
    String getDestinationFolderPath()
    {
        destinationFolderPathProperty.getOrNull()
    }

    void setDestinationFolderPath(
        String value)
    {
        destinationFolderPathProperty.set(value)
    }

    void setDestinationFolderPathProvider(
        Provider<String> value)
    {
        destinationFolderPathProperty.set(value)
    }

    @Optional
    @Input
    String getDestinationFolderId()
    {
        destinationFolderIdProperty.getOrNull()
    }

    void setDestinationFolderId(
        String value)
    {
        destinationFolderIdProperty.set(value)
    }

    void setDestinationFolderIdProvider(
        Provider<String> value)
    {
        destinationFolderIdProperty.set(value)
    }

    @Input
    List<String> getDestinationNames()
    {
        destinationNamesProperty.getOrElse(new ArrayList<String>())
    }

    void setDestinationNames(
        List<String> value)
    {
        destinationNamesProperty.set(value)
    }

    void setDestinationNamesProvider(
        Provider<List<String>> value)
    {
        destinationNamesProperty.set(value)
    }

    @InputFiles
    List<File> getFiles()
    {
        filesProperty.get()
    }

    void setFiles(
        List<File> value)
    {
        filesProperty.set(value)
    }

    void setFilesProvider(
        Provider<List<File>> value)
    {
        filesProperty.set(value)
    }

    String getClientId()
    {
        clientIdProperty.getOrElse("")
    }

    void setClientId(
        String value)
    {
        clientIdProperty.set(value)
    }

    void setClientIdProvider(
        Provider<String> value)
    {
        clientIdProperty.set(value)
    }

    String getClientSecret()
    {
        clientSecretProperty.getOrElse("")
    }

    void setClientSecret(
        String value)
    {
        clientSecretProperty.set(value)
    }

    void setClientSecretProvider(
        Provider<String> value)
    {
        clientSecretProperty.set(value)
    }

    @Input
    List<Permission> getPermissions()
    {
        permissionsProperty.getOrElse(DEFAULT_PERMISSIONS)
    }

    void setPermissions(
        List<Permission> value)
    {
        permissionsProperty.set(value)
    }

    void setPermissionsProvider(
        Provider<List<Permission>> value)
    {
        permissionsProperty.set(value)
    }

    @Input
    Boolean getUpdateIfExists()
    {
        updateIfExistsProperty.getOrElse(DEFAULT_UPDATE_IF_EXISTS)
    }

    void setUpdateIfExists(
        Boolean value)
    {
        updateIfExistsProperty.set(value)
    }

    void setUpdateIfExistsProvider(
        Provider<Boolean> value)
    {
        updateIfExistsProperty.set(value)
    }

    @Internal
    File getCredentialsDir()
    {
        credentialsDirProperty.present ? credentialsDirProperty.get()
            : new File(System.getProperty('user.home'),
                '.credentials/google-drive-uploader')
    }

    void setCredentialsDir(
        File value)
    {
        credentialsDirProperty.set(value)
    }

    void setCredentialsDirProvider(
        Provider<File> value)
    {
        credentialsDirProperty.set(value)
    }

    @Internal
    File getServiceAccountJson()
    {
        serviceAccountJsonProperty.getOrNull()
    }

    void setServiceAccountJson(
            File value)
    {
        serviceAccountJsonProperty.set(value)
    }

    void setServiceAccountJsonProvider(
            Provider<File> value)
    {
        serviceAccountJsonProperty.set(value)
    }
}
