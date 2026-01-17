package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.RadioButton;
import javafx.scene.layout.HBox;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.input.DragEvent;
import javafx.scene.input.TransferMode;
import java.util.List;

public class MainController {

    @FXML
    private TextField inputFileField;
    @FXML
    private TextField outputFileField;

    @FXML
    private PasswordField passwordField;
    @FXML
    private TextField passwordTextField;
    @FXML
    private PasswordField confirmPasswordField;
    @FXML
    private TextField confirmPasswordTextField;
    @FXML
    private Button encryptButton;
    @FXML
    private Button decryptButton;
    @FXML
    private Button browseButton;

    @FXML
    private CheckBox shredOriginalCheck;
    @FXML
    private Button selectButton;
    @FXML
    private Button generateButton;
    @FXML
    private CheckBox showKeyCheck;
    @FXML
    private ProgressBar strengthBar;
    @FXML
    private Label strengthLabel;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private Label statusText;
    @FXML
    private ToggleGroup modeGroup;
    @FXML
    private ToggleGroup algoGroup;
    @FXML
    private RadioButton gcmRadio;
    @FXML
    private RadioButton cbcRadio;
    @FXML
    private HBox outputBox;
    @FXML
    private CheckBox customOutputCheck;
    @FXML
    private Label currentUserLabel;
    @FXML
    private ListView<String> logsListView;

    // Admin Controls
    @FXML
    private TabPane mainTabPane;
    @FXML
    private Tab adminTab;
    @FXML
    private TextField regUsernameField;
    @FXML
    private PasswordField regPasswordField;
    @FXML
    private PasswordField regConfirmPasswordField;
    @FXML
    private Label regStatusLabel;

    private String currentUser;

    public void initSession(String username) {
        this.currentUser = username;
        if (currentUserLabel != null) {
            currentUserLabel.setText(username);
        }

        // Admin Logic: Show/Hide Admin Tab
        if (adminTab != null && mainTabPane != null) {
            if ("admin".equals(username)) {
                if (!mainTabPane.getTabs().contains(adminTab)) {
                    mainTabPane.getTabs().add(adminTab);
                }
            } else {
                mainTabPane.getTabs().remove(adminTab);
            }
        }

        loadLogs();
    }

    @FXML
    private void initialize() {
        if (progressBar != null)
            progressBar.setProgress(0);
        if (statusText != null)
            statusText.setText("Ready");
        // Hide admin tab by default until initialized
        if (mainTabPane != null && adminTab != null) {
            mainTabPane.getTabs().remove(adminTab);
        }

        // Mode Toggle Listener
        if (modeGroup != null) {
            modeGroup.selectedToggleProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal != null) {
                    boolean isDecrypt = "Decrypt".equals(((RadioButton) newVal).getText());
                    encryptButton.setDisable(isDecrypt);
                    decryptButton.setDisable(!isDecrypt);

                    // Toggle customized output container based on mode
                    if (isDecrypt) {
                        // Decrypt mode: hide output by default, show checkbox
                        outputBox.setVisible(false);
                        outputBox.setManaged(false);
                        customOutputCheck.setVisible(true);
                        customOutputCheck.setManaged(true);
                        if (shredOriginalCheck != null) {
                            shredOriginalCheck.setVisible(false);
                            shredOriginalCheck.setManaged(false);
                        }
                    } else {
                        // Encrypt mode: show output always (implied auto or manual)
                        outputBox.setVisible(true);
                        outputBox.setManaged(true);
                        customOutputCheck.setVisible(false);
                        customOutputCheck.setManaged(false);
                        if (shredOriginalCheck != null) {
                            shredOriginalCheck.setVisible(true);
                            shredOriginalCheck.setManaged(true);
                        }
                    }
                }
            });
        }

        // Initialize custom output checkbox listener
        if (customOutputCheck != null) {
            customOutputCheck.selectedProperty().addListener((obs, oldVal, isSelected) -> {
                if (outputBox != null) {
                    outputBox.setVisible(isSelected);
                    outputBox.setManaged(isSelected);
                }
            });
        }

        // Password Binding Logic (Bi-directional sync)
        if (passwordField != null && passwordTextField != null) {
            passwordTextField.managedProperty().bind(passwordTextField.visibleProperty());
            passwordField.managedProperty().bind(passwordField.visibleProperty());
            passwordTextField.textProperty().bindBidirectional(passwordField.textProperty());

            // Password Strength Listener
            passwordField.textProperty().addListener((obs, oldVal, newVal) -> updatePasswordStrength(newVal));
        }
        if (confirmPasswordField != null && confirmPasswordTextField != null) {
            confirmPasswordTextField.managedProperty().bind(confirmPasswordTextField.visibleProperty());
            confirmPasswordField.managedProperty().bind(confirmPasswordField.visibleProperty());
            confirmPasswordTextField.textProperty().bindBidirectional(confirmPasswordField.textProperty());
        }

        // Context Menu for Browse Button (File or Folder)
        if (browseButton != null) {
            javafx.scene.control.ContextMenu menu = new javafx.scene.control.ContextMenu();
            javafx.scene.control.MenuItem fileItem = new javafx.scene.control.MenuItem("Select File");
            fileItem.setOnAction(e -> onBrowse());
            javafx.scene.control.MenuItem folderItem = new javafx.scene.control.MenuItem("Select Folder");
            folderItem.setOnAction(e -> onBrowseFolder());
            menu.getItems().addAll(fileItem, folderItem);
            browseButton.setContextMenu(menu);
            browseButton.setTooltip(new javafx.scene.control.Tooltip("Right-click to select a folder"));
        }
    }

    @FXML
    private void onBrowse() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Input File");
        File f = chooser.showOpenDialog(browseButton.getScene().getWindow());
        if (f != null)
            inputFileField.setText(f.getAbsolutePath());
    }

    private void onBrowseFolder() {
        javafx.stage.DirectoryChooser chooser = new javafx.stage.DirectoryChooser();
        chooser.setTitle("Select Input Folder");
        File f = chooser.showDialog(browseButton.getScene().getWindow());
        if (f != null)
            inputFileField.setText(f.getAbsolutePath());
    }

    @FXML
    private void onSelectOutput() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Output File");

        // Smart suggestion logic
        String currentInput = inputFileField.getText();
        if (currentInput != null && !currentInput.isEmpty()) {
            Path in = Paths.get(currentInput);
            chooser.setInitialDirectory(in.getParent().toFile());

            boolean isDecrypt = "Decrypt".equals(((RadioButton) modeGroup.getSelectedToggle()).getText());
            if (isDecrypt) {
                // Try to get original name
                String suggestion = CryptoService.getDecryptedName(in);
                if (suggestion != null)
                    chooser.setInitialFileName(suggestion);
                else {
                    String n = in.getFileName().toString();
                    if (n.endsWith(".enc"))
                        chooser.setInitialFileName(n.substring(0, n.length() - 4));
                    else
                        chooser.setInitialFileName(n + ".decrypted");
                }
            } else {
                // Encrypt mode: append .enc or .encrypted?
                // Actually usually we just let user pick or we default to name.enc
                chooser.setInitialFileName(in.getFileName().toString() + ".enc");
            }
        }

        File f = chooser.showSaveDialog(selectButton.getScene().getWindow());
        if (f != null)
            outputFileField.setText(f.getAbsolutePath());
    }

    @FXML
    private void onEncrypt() {
        process(true);
    }

    @FXML
    private void onDecrypt() {
        process(false);
    }

    private void process(boolean encrypt) {
        String in = inputFileField.getText();
        String outText = outputFileField.getText();
        String pwd = passwordField.getText();
        String conf = confirmPasswordField.getText();

        if (in == null || in.isBlank()) {
            setStatus("Select an input file");
            return;
        }

        Path inPath = Paths.get(in);
        if (!Files.exists(inPath)) {
            setStatus("Error: Input file/folder does not exist");
            return;
        }
        Path outPath = null;

        if (encrypt) {
            if (outText == null || outText.isBlank()) {
                setStatus("Select an output file");
                return;
            }
            outPath = Paths.get(outText);
        } else {
            // Decrypt Logic
            if (customOutputCheck.isSelected()) {
                if (outText == null || outText.isBlank()) {
                    setStatus("Select an output file");
                    return;
                }
                outPath = Paths.get(outText);
            } else {
                // Auto-derive
                String derivedName = CryptoService.getDecryptedName(inPath);
                if (derivedName == null) {
                    // Fallback simple
                    String n = inPath.getFileName().toString();
                    if (n.endsWith(".enc"))
                        derivedName = n.substring(0, n.length() - 4);
                    else
                        derivedName = n + ".decrypted";
                }
                outPath = inPath.getParent().resolve(derivedName);
            }
        }

        if (pwd == null || pwd.isEmpty()) {
            setStatus("Enter a password");
            return;
        }
        if (encrypt && !pwd.equals(conf)) {
            setStatus("Passwords do not match");
            return;
        }

        char[] password = pwd.toCharArray();
        final Path finalOutPath = outPath; // for lambda

        if (Files.exists(finalOutPath)) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION,
                    "Output file already exists: " + finalOutPath.getFileName() + "\nOverwrite?",
                    ButtonType.YES, ButtonType.NO);
            alert.showAndWait();
            if (alert.getResult() != ButtonType.YES) {
                return;
            }
        }

        if (encrypt && CryptoService.isEncrypted(inPath)) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION,
                    "The file appears to be already encrypted. Do you want to encrypt it again? (Double Encryption)",
                    ButtonType.YES, ButtonType.NO);
            alert.showAndWait();
            if (alert.getResult() != ButtonType.YES) {
                return;
            }
        }

        // Shred Warning
        if (encrypt && shredOriginalCheck != null && shredOriginalCheck.isSelected()) {
            Alert alert = new Alert(Alert.AlertType.WARNING,
                    "SECURITY WARNING:\n\nYou have passed 'Securely Shred Source File'.\n\nThe original file '"
                            + inPath.getFileName()
                            + "' will be PERMANENTLY destroyed (overwritten and deleted) after encryption.\n\nThis cannot be undone. Are you sure?",
                    ButtonType.YES, ButtonType.CANCEL);
            alert.showAndWait();
            if (alert.getResult() != ButtonType.YES) {
                return;
            }
        }

        String action = encrypt ? "Encrypting" : "Decrypting";
        setStatus(action + "...");
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        disableButtons(true);

        CompletableFuture.runAsync(() -> {
            try {
                if (encrypt) {
                    CryptoService.EncryptionMode mode = gcmRadio.isSelected() ? CryptoService.EncryptionMode.GCM
                            : CryptoService.EncryptionMode.CBC;
                    CryptoService.encrypt(inPath, finalOutPath, password, mode);

                    // Secure Shredder Logic
                    if (encrypt && shredOriginalCheck != null && shredOriginalCheck.isSelected()) {
                        Platform.runLater(() -> setStatus("Shredding original file..."));
                        CryptoService.shredFile(inPath);
                    }
                } else {
                    CryptoService.decrypt(inPath, finalOutPath, password);
                }

                Platform.runLater(() -> {
                    progressBar.setProgress(1.0);
                    setStatus(encrypt
                            ? "Encryption successful!" + (shredOriginalCheck.isSelected() ? " Original shredded." : "")
                            : "Decryption successful! Saved: " + finalOutPath.getFileName());
                    // Log for the current user (privacy: users see their own logs)
                    String op = encrypt ? "ENCRYPT" : "DECRYPT";
                    if (encrypt && shredOriginalCheck.isSelected())
                        op += "_SHRED";
                    DBController.logActivity(currentUser, op,
                            inPath.getFileName().toString());
                    loadLogs();

                    // Auto-clear inputs on success
                    if (inputFileField != null)
                        inputFileField.clear();
                    if (outputFileField != null)
                        outputFileField.clear();
                    if (passwordField != null)
                        passwordField.clear();
                    if (confirmPasswordField != null)
                        confirmPasswordField.clear();
                });
            } catch (IOException | GeneralSecurityException ex) {
                Platform.runLater(() -> {
                    String msg = ex.getMessage();
                    // Check for specific crypto errors that indicate wrong password
                    if (ex instanceof javax.crypto.AEADBadTagException
                            || ex instanceof javax.crypto.BadPaddingException) {
                        msg = "Incorrect Password or Corrupted File";
                    } else if (msg != null && msg.contains("Tag mismatch")) {
                        // Fallback text check
                        msg = "Incorrect Password or Corrupted File";
                    }
                    setStatus("Error: " + msg);
                    progressBar.setProgress(0);
                });
                ex.printStackTrace();
            } finally {
                Arrays.fill(password, '\0');
                Platform.runLater(() -> {
                    disableButtons(false);
                    // Stop progress bar (reset to 0)
                    progressBar.setProgress(0);
                });
            }
        });
    }

    @FXML
    private void onGenerate() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++)
            sb.append(chars.charAt((int) (Math.random() * chars.length())));

        // Because fields are bound, setting one updates the other
        passwordField.setText(sb.toString());
        confirmPasswordField.setText(sb.toString());
        setStatus("Generated secure password");
    }

    @FXML
    private void onShowKeyToggle() {
        boolean show = showKeyCheck.isSelected();
        if (passwordField != null && passwordTextField != null) {
            passwordTextField.setVisible(show);
            passwordField.setVisible(!show);
        }
        if (confirmPasswordField != null && confirmPasswordTextField != null) {
            confirmPasswordTextField.setVisible(show);
            confirmPasswordField.setVisible(!show);
        }

        if (show)
            setStatus("Key visible");
        else
            setStatus("Key hidden");
    }

    @FXML
    private void updatePasswordStrength(String password) {
        if (strengthBar == null || strengthLabel == null)
            return;

        if (password == null || password.isEmpty()) {
            strengthBar.setProgress(0);
            strengthLabel.setText("");
            strengthBar.setStyle("");
            return;
        }

        double strength = 0;
        int length = password.length();

        if (length >= 8)
            strength += 0.25;
        if (length >= 12)
            strength += 0.25;
        if (password.matches(".*[A-Z].*"))
            strength += 0.15;
        if (password.matches(".*[a-z].*"))
            strength += 0.15;
        if (password.matches(".*[0-9].*"))
            strength += 0.10;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*"))
            strength += 0.10;

        // Cap at 1.0
        if (strength > 1.0)
            strength = 1.0;

        strengthBar.setProgress(strength);

        String color = "red";
        String text = "Weak";

        if (strength < 0.3) {
            color = "red";
            text = "Weak";
        } else if (strength < 0.7) {
            color = "orange";
            text = "Medium";
        } else {
            color = "green";
            text = "Strong";
        }

        strengthBar.setStyle("-fx-accent: " + color + ";");
        strengthLabel.setText(text);
        strengthLabel.setStyle("-fx-text-fill: " + color + "; -fx-font-size: 10px;");
    }

    @FXML
    private void onShredTool() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select File to Shred");
        File file = chooser.showOpenDialog(browseButton.getScene().getWindow());
        if (file == null)
            return;

        Path path = file.toPath();

        Alert alert = new Alert(Alert.AlertType.WARNING,
                "SECURITY WARNING:\n\nYou are about to shred:\n" + file.getName()
                        + "\n\nThis file will be PERMANENTLY destroyed (overwritten and deleted).\n\nThis cannot be undone. Are you sure?",
                ButtonType.YES, ButtonType.CANCEL);
        alert.showAndWait();
        if (alert.getResult() != ButtonType.YES)
            return;

        try {
            CryptoService.shredFile(path);
            Alert info = new Alert(Alert.AlertType.INFORMATION, "File shredded successfully!", ButtonType.OK);
            info.showAndWait();

            // Log this standalone action
            DBController.logActivity(currentUser, "SHRED_TOOL", file.getName());
            loadLogs();

        } catch (IOException e) {
            Alert err = new Alert(Alert.AlertType.ERROR, "Error shredding file: " + e.getMessage(), ButtonType.OK);
            err.showAndWait();
        }
    }

    @FXML
    private void onClear() {
        if (inputFileField != null)
            inputFileField.clear();
        if (outputFileField != null)
            outputFileField.clear();
        if (passwordField != null)
            passwordField.clear(); // Binds to TextField too
        if (confirmPasswordField != null)
            confirmPasswordField.clear();
        if (progressBar != null)
            progressBar.setProgress(0);
        if (statusText != null)
            statusText.setText("Ready");
        if (customOutputCheck != null)
            customOutputCheck.setSelected(false);
    }

    @FXML
    private void handleDragOver(DragEvent event) {
        if (event.getDragboard().hasFiles()) {
            event.acceptTransferModes(TransferMode.COPY);
        }
        event.consume();
    }

    @FXML
    private void handleDragDropped(DragEvent event) {
        if (event.getDragboard().hasFiles()) {
            List<File> files = event.getDragboard().getFiles();
            if (files != null && !files.isEmpty()) {
                File f = files.get(0);
                if (inputFileField != null) {
                    inputFileField.setText(f.getAbsolutePath());
                    // Auto-focus output or clear output if needed?
                    // For now just set input
                }
            }
            event.setDropCompleted(true);
        } else {
            event.setDropCompleted(false);
        }
        event.consume();
    }

    @FXML
    private void onAddUser() {
        if (!"admin".equals(currentUser)) {
            regStatusLabel.setText("Access Denied: Admin only.");
            return;
        }

        String newDeviceUser = regUsernameField.getText().trim();
        String pass = regPasswordField.getText();
        String conf = regConfirmPasswordField.getText();

        if (newDeviceUser.isEmpty() || pass.isEmpty()) {
            regStatusLabel.setText("All fields are required");
            return;
        }

        if (!pass.equals(conf)) {
            regStatusLabel.setText("Passwords do not match");
            return;
        }

        if (DBController.registerUser(newDeviceUser, pass)) {
            regStatusLabel.setText("User '" + newDeviceUser + "' created successfully!");
            regUsernameField.clear();
            regPasswordField.clear();
            regConfirmPasswordField.clear();
        } else {
            regStatusLabel.setText("Failed: Username might be taken.");
        }
    }

    @FXML
    public void loadLogs() {
        if (logsListView != null && currentUser != null) {
            logsListView.getItems().clear();
            // This pulls logs ONLY for the currentUser, ensuring privacy.
            logsListView.getItems().addAll(DBController.getLogs(currentUser));
        }
    }

    @FXML
    private void onLogout() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/Login.fxml"));
            Parent root = loader.load();
            Stage stage = (Stage) inputFileField.getScene().getWindow();
            stage.setScene(new Scene(root));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void onExit() {
        Platform.exit();
        System.exit(0);
    }

    private void disableButtons(boolean disable) {
        if (encryptButton != null)
            encryptButton.setDisable(disable);
        if (decryptButton != null)
            decryptButton.setDisable(disable);
        if (browseButton != null)
            browseButton.setDisable(disable);
        if (selectButton != null)
            selectButton.setDisable(disable);
        if (generateButton != null)
            generateButton.setDisable(disable);
    }

    private void setStatus(String msg) {
        if (statusText != null)
            statusText.setText(msg);
    }
}