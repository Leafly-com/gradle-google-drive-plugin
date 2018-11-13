package ru.kinca.gradle.googledrive

import com.google.api.services.drive.model.Permission

import org.gradle.api.Project
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider

/**
 * Extension that allows to configure the plugin in a declarative way.
 *
 * @author Valentin Naumov
 */
class ConfigExtension
{
    private final Property<String> destinationFolderPathProperty

    private final Property<String> destinationFolderIdProperty

    private final Property<List<String>> destinationNamesProperty

    private final Property<List<File>> filesProperty

    private final Property<String> clientIdProperty

    private final Property<String> clientSecretProperty

    private final Property<List<Permission>> permissionProperty

    private final Property<Boolean> updateIfExistsProperty

    private final Property<File> credentialsDirProperty

    private final Property<File> serviceAccountJsonProperty

    ConfigExtension(
        Project project)
    {
        destinationFolderPathProperty = project.objects.property(String)
        destinationFolderIdProperty = project.objects.property(String)
        destinationNamesProperty = project.objects.property(List)
        filesProperty = project.objects.property(List)
        clientIdProperty = project.objects.property(String)
        clientSecretProperty = project.objects.property(String)
        permissionProperty = project.objects.property(List)

        // Wrapper type properties are assigned default values, we need to
        // override
        updateIfExistsProperty = project.objects.property(Boolean)
        updateIfExistsProperty.set(null as Boolean)

        credentialsDirProperty = project.objects.property(File)

        serviceAccountJsonProperty = project.objects.property(File)
    }

    String getDestinationFolderPath()
    {
        destinationFolderPathProperty.getOrNull()
    }

    void setDestinationFolderPath(
        String value)
    {
        destinationFolderPathProperty.set(value)
    }

    Provider<String> getDestinationFolderPathProvider()
    {
        destinationFolderPathProperty
    }

    String getDestinationFolderId()
    {
        destinationFolderIdProperty.getOrNull()
    }

    void setDestinationFolderId(
        String value)
    {
        destinationFolderIdProperty.set(value)
    }

    Provider<String> getDestinationFolderIdProvider()
    {
        destinationFolderIdProperty
    }

    List<String> getDestinationNames()
    {
        destinationNamesProperty.get()
    }

    void setDestinationNames(
        List<String> value)
    {
        destinationNamesProperty.set(value)
    }

    Provider<List<String>> getDestinationNamesProvider()
    {
        destinationNamesProperty
    }

    List<File> getFiles()
    {
        filesProperty.get()
    }

    void setFiles(
        List<File> value)
    {
        filesProperty.set(value)
    }

    Provider<List<File>> getFilesProvider()
    {
        filesProperty
    }

    String getClientId()
    {
        clientIdProperty.get()
    }

    void setClientId(
        String value)
    {
        clientIdProperty.set(value)
    }

    Provider<String> getClientIdProvider()
    {
        clientIdProperty
    }

    String getClientSecret()
    {
        clientSecretProperty.get()
    }

    void setClientSecret(
        String value)
    {
        clientSecretProperty.set(value)
    }

    Provider<String> getClientSecretProvider()
    {
        clientSecretProperty
    }

    List<Permission> getPermissions()
    {
        permissionProperty.get()
    }

    void setPermissions(
        List<Permission> value)
    {
        permissionProperty.set(value)
    }

    Provider<List<Permission>> getPermissionsProvider()
    {
        permissionProperty
    }

    Boolean getUpdateIfExists()
    {
        updateIfExistsProperty.get()
    }

    void setUpdateIfExists(
        Boolean value)
    {
        updateIfExistsProperty.set(value)
    }

    Provider<Boolean> getUpdateIfExistsProvider()
    {
        updateIfExistsProperty
    }

    File getCredentialsDir()
    {
        credentialsDirProperty.get()
    }

    /**
     * Sets the location where Google Drive client's credentials will be stored.
     * You may want to have a separate dir for each project.
     *
     * Default is <code>${user.home}/.credentials/google-drive-uploader'</code>.
     *
     * @param value
     *        credentials directory.
     */
    void setCredentialsDir(
        File value)
    {
        credentialsDirProperty.set(value)
    }

    Provider<File> getCredentialsDirProvider()
    {
        credentialsDirProperty
    }

    File getServiceAccountJson()
    {
        serviceAccountJsonProperty.get()
    }

    void setServiceAccountJson(
            File value)
    {
        serviceAccountJsonProperty.set(value)
    }

    Provider<File> getServiceAccountJsonProvider()
    {
        serviceAccountJsonProperty
    }
}
