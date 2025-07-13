package google;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.util.store.FileDataStoreFactory;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.drive.DriveScopes;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.lang.String;

import io.github.cdimascio.dotenv.Dotenv;

public class GoogleAuthManager {
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static String CLIENT_CREDENTIALS_FILE_PATH; 
    private static String TOKENS_DIRECTORY_PATH; 
    private static String CREDENTIAL_USER_ID; 
    private static int port; 
    private GoogleClientSecrets clientSecrets;
    private GoogleAuthorizationCodeFlow flow;
    private LocalServerReceiver receiver;
    private NetHttpTransport HTTP_TRANSPORT;
    Credential cred;

    // modifying these scopes requires you to delete previously saved user tokens and get fresh ones
    private static final List<String> SCOPES = Collections.singletonList(DriveScopes.DRIVE);

    public GoogleAuthManager () { 
        Dotenv dotenv = Dotenv.load(); 
        
        CLIENT_CREDENTIALS_FILE_PATH = dotenv.get("CLIENT_CREDENTIALS_FILE_PATH");
        TOKENS_DIRECTORY_PATH = dotenv.get("TOKENS_DIRECTORY_PATH");
        CREDENTIAL_USER_ID = dotenv.get("CREDENTIAL_USER_ID");
        port = Integer.parseInt(dotenv.get("RECEIVER_PORT"));
    }

    public void initialize() {
        try {
            authorizeUser();
        } catch (Exception e) {
            System.out.println("Error initializing GoogleAuthManager: " + e.getMessage());
        }
    }

    void authorizeUser () throws IOException, GeneralSecurityException  {
        HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        InputStream secrets = GoogleAuthManager.class.getResourceAsStream(CLIENT_CREDENTIALS_FILE_PATH);

        // assuming the client secrets file is always in your specified directory,
        // this is not needed, can be removed
        if (secrets == null) {
            throw new FileNotFoundException("Resource not found: " + CLIENT_CREDENTIALS_FILE_PATH);
        }

        this.clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(secrets));

        this.flow = new GoogleAuthorizationCodeFlow.Builder(HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline") 
                .build();

        this.cred = flow.loadCredential(CREDENTIAL_USER_ID);

        if(this.cred == null) this.getFreshCredentials();
        
        if(this.cred.getExpiresInSeconds() < 0) this.refreshCredentials(); 
    }

    void getFreshCredentials() {
        try {
            this.receiver = new LocalServerReceiver.Builder().setPort(port).build();
            this.cred = new AuthorizationCodeInstalledApp(this.flow, this.receiver).authorize(CREDENTIAL_USER_ID);
        } catch (IOException e) {
            // TO DO: Log the errors into a file and return appropriate err message
            System.out.println("Error getting fresh credentials @ GoogleAuthManager: " + e.getMessage());
        }
    }

    void refreshCredentials() {
        try {
            this.cred.refreshToken(); 
        } catch (IOException e) {
            // TO DO: Log the errors into a file
            this.getFreshCredentials();
        }
    }

    public Credential getUserCredentials() {
        return this.cred;
    }
}
