let currentTaskId = null;
let commands = {};
// Live status and task monitoring variables removed

// Initialize drag and drop when page loads
function initializeDragAndDrop() {
    const uploadArea = document.getElementById("uploadArea");

    // Add click handler for file selection
    uploadArea.addEventListener("click", function (e) {
        // Only trigger if not dragging
        if (!uploadArea.classList.contains("dragging")) {
            document.getElementById("fileInput").click();
        }
    });

    // Prevent default drag behaviors
    ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop area when item is dragged over it
    ["dragenter", "dragover"].forEach(eventName => {
        uploadArea.addEventListener(eventName, highlight, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        uploadArea.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    uploadArea.addEventListener("drop", handleDrop, false);
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function highlight(e) {
    const uploadArea = document.getElementById("uploadArea");
    uploadArea.classList.add("dragging");
    uploadArea.style.borderColor = "#90caf9";
    uploadArea.style.backgroundColor = "rgba(100, 181, 246, 0.1)";
    uploadArea.style.transform = "scale(1.02)";
    uploadArea.style.boxShadow = "0 8px 25px rgba(100, 181, 246, 0.3)";
}

function unhighlight(e) {
    const uploadArea = document.getElementById("uploadArea");
    uploadArea.classList.remove("dragging");
    uploadArea.style.borderColor = "#64b5f6";
    uploadArea.style.backgroundColor = "";
    uploadArea.style.transform = "scale(1)";
    uploadArea.style.boxShadow = "";
}

function handleDrop(e) {
    console.log("File(s) dropped");
    const dt = e.dataTransfer;
    const files = dt.files;

    console.log("Number of files:", files.length);

    if (files.length > 0) {
        const file = files[0];
        console.log("File name:", file.name, "Size:", file.size);

        // Check file extension
        const allowedExtensions = [".dd", ".raw", ".mem", ".dmp", ".img", ".vmem", ".bin"];
        const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf("."));

        console.log("File extension:", fileExtension);

        if (allowedExtensions.includes(fileExtension)) {
            console.log("Valid file type, uploading...");
            uploadFileData(file);
        } else {
            console.log("Invalid file type");
            document.getElementById("uploadStatus").innerHTML =
                `<div class="status error">❌ Invalid file type "${fileExtension}". Supported: ${allowedExtensions.join(", ")}</div>`;
        }
    } else {
        console.log("No files in drop event");
    }
}

async function uploadFileData(file) {
    const formData = new FormData();
    formData.append("file", file);

    document.getElementById("uploadStatus").innerHTML = `<div class="status running">⏳ Uploading ${file.name}...</div>`;

    try {
        const response = await fetch("/upload", {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            document.getElementById("uploadStatus").innerHTML = `<div class="status completed">✅ ${result.message}</div>`;
            refreshFiles();
        } else {
            document.getElementById("uploadStatus").innerHTML = `<div class="status error">❌ ${result.error}</div>`;
        }
    } catch (error) {
        document.getElementById("uploadStatus").innerHTML = `<div class="status error">❌ Upload failed: ${error.message}</div>`;
    }
}

function showTab(tabName) {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));

    event.target.classList.add("active");
    document.getElementById(tabName + "-tab").classList.remove("hidden");

    if (tabName === "analyze") {
        refreshMemorySelect();
        // Live status updates removed
    }
    if (tabName === "results") refreshResults();
    if (tabName === "help") loadHelpDocumentation();
}

// Live status update functions removed

function openHelpInNewTab() {
    window.open("/help", "_blank");
}

function loadHelpDocumentation() {
    // This function is called when switching to the help tab
    // No action needed - user clicks button to open help
    console.log("Help tab activated");
}

async function uploadFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    if (!file) return;

    await uploadFileData(file);
    fileInput.value = "";
}

async function refreshFiles() {
    try {
        const response = await fetch("/files");
        const files = await response.json();

        const fileList = document.getElementById("fileList");
        fileList.innerHTML = "";

        // Filter to show only memory files in the upload section
        const memoryExtensions = ['.dd', '.raw', '.mem', '.dmp', '.img', '.vmem', '.bin'];
        const memoryFiles = files.filter(file => {
            const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
            return memoryExtensions.includes(extension);
        });

        if (memoryFiles.length === 0) {
            fileList.innerHTML = "<p>No memory dump files found. Upload memory files with extensions: .dd, .raw, .mem, .dmp, .img, .vmem, .bin</p>";
            return;
        }

        memoryFiles.forEach(file => {
            const fileItem = document.createElement("div");
            fileItem.className = "file-item";
            fileItem.innerHTML = `
                <div>
                    <strong>💾 ${file.name}</strong><br>
                    <small>${formatFileSize(file.size)} - ${new Date(file.modified).toLocaleString()}</small>
                </div>
                <div>
                    <button class="btn btn-warning" onclick="downloadFile('${file.name}')">⬇️ Download</button>
                    <button class="btn btn-danger" onclick="deleteFile('${file.name}')">🗑️ Delete</button>
                </div>
            `;
            fileList.appendChild(fileItem);
        });
    } catch (error) {
        console.error("Error refreshing files:", error);
    }
}

async function refreshMemorySelect() {
    try {
        const response = await fetch("/files");
        const files = await response.json();

        const select = document.getElementById("memorySelect");
        select.innerHTML = "<option value=''>Select memory dump...</option>";

        files.filter(f => /\.(dd|raw|mem|dmp|img|vmem|bin)$/i.test(f.name))
            .forEach(file => {
                const option = document.createElement("option");
                option.value = file.name;
                option.textContent = file.name;
                select.appendChild(option);
            });
    } catch (error) {
        console.error("Error refreshing memory select:", error);
    }
}

async function loadCommands() {
    const osType = document.getElementById("osSelect").value;
    if (!osType) {
        document.getElementById("commandGrid").innerHTML = "";
        const ws = document.getElementById("windows-shortcuts");
        if (ws) ws.classList.add("hidden");
        return;
    }

    try {
        const response = await fetch("/commands");
        commands = await response.json();

        const grid = document.getElementById("commandGrid");
        grid.innerHTML = "";

        const osCommands = commands[osType] || {};

        // Toggle Windows shortcuts visibility
        const ws = document.getElementById("windows-shortcuts");
        if (ws) {
            if (osType === 'Windows') ws.classList.remove('hidden');
            else ws.classList.add('hidden');
        }

        Object.keys(osCommands).forEach(category => {
            const categoryDiv = document.createElement("div");
            categoryDiv.className = "command-category";

            const title = document.createElement("h4");
            title.textContent = category;
            categoryDiv.appendChild(title);

            Object.keys(osCommands[category]).forEach(cmd => {
                const button = document.createElement("button");
                button.className = "command-btn btn";

                // Extract command name (e.g., "windows.cmdline.CmdLine" -> "CmdLine")
                const commandName = cmd.split('.').pop();
                button.textContent = commandName;

                // Set the full description as tooltip
                const description = osCommands[category][cmd];
                button.title = description;

                button.onclick = () => runCommand(cmd);

                categoryDiv.appendChild(button);
            });

            grid.appendChild(categoryDiv);
        });
    } catch (error) {
        console.error("Error loading commands:", error);
    }
}

// Run Windows BitLocker helper
async function runWindowsBitlocker() {
    const memoryFile = document.getElementById("memorySelect").value;
    const osType = document.getElementById("osSelect").value;
    if (!memoryFile) {
        alert("Please select a memory dump file first");
        return;
    }
    if (osType !== 'Windows') {
        alert("Please select Windows as the operating system to use this shortcut");
        return;
    }
    try {
        const response = await fetch('/windows-bitlocker', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ memory_file: memoryFile })
        });
        const result = await response.json();
        if (response.ok) {
            alert('BitLocker recovery started! Check the Results tab later for output. Any .fvek keys will appear in Results or be downloadable from /data.');
        } else {
            alert(`Failed to start BitLocker helper: ${result.error || response.status}`);
        }
    } catch (err) {
        alert(`Error starting BitLocker helper: ${err.message}`);
    }
}

async function runCommand(command) {
    const memoryFile = document.getElementById("memorySelect").value;
    const osType = document.getElementById("osSelect").value;

    if (!memoryFile || !osType) {
        alert("Please select a memory dump and operating system");
        return;
    }

    // Check if this plugin requires arguments
    try {
        const argsResponse = await fetch(`/plugin-args/${command}`);
        const pluginArgs = await argsResponse.json();

        let argsPayload = {};

        // If plugin has arguments, show dialog to collect them
        if (Object.keys(pluginArgs).length > 0) {
            const argumentsCollected = await collectArguments(command, pluginArgs);
            if (argumentsCollected === null) {
                return; // User cancelled
            }
            argsPayload = argumentsCollected;
        }

        console.log(`[DEBUG] Starting command: ${command} for ${memoryFile} (${osType}) with args:`, arguments);

        const response = await fetch("/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                memory_file: memoryFile,
                os_type: osType,
                command: command,
                arguments: argsPayload
            })
        });

        const result = await response.json();
        console.log(`[DEBUG] Run command response:`, result);

        if (response.ok) {
            currentTaskId = result.task_id;
            console.log(`[DEBUG] Task started with ID: ${currentTaskId}`);
            // Task monitoring removed - results will be available in Results tab
            alert(`Command started successfully! Check the Results tab for output when complete.`);
        } else {
            console.error(`[ERROR] Failed to start command:`, result);
            alert(`Failed to start command: ${result.error}`);
        }
    } catch (error) {
        console.error(`[ERROR] Error running command:`, error);
        alert(`Error running command: ${error.message}`);
    }
}

async function collectArguments(command, pluginArgs) {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'argument-modal';
        modal.innerHTML = `
            <div class="modal-content">
                <h3>Plugin Arguments for ${command}</h3>
                <p>This plugin supports additional arguments. Fill in the ones you need:</p>
                <form id="argumentForm">
                    ${Object.entries(pluginArgs).map(([argName, description]) => `
                        <div class="argument-field">
                            <label for="arg_${argName}">${argName}:</label>
                            <input type="text" id="arg_${argName}" name="${argName}" placeholder="${description}">
                            <small>${description}</small>
                        </div>
                    `).join('')}
                    <div class="modal-buttons">
                        <button type="button" onclick="submitArguments()" class="btn btn-primary">Run Command</button>
                        <button type="button" onclick="cancelArguments()" class="btn btn-secondary">Cancel</button>
                    </div>
                </form>
            </div>
        `;

        document.body.appendChild(modal);

        window.submitArguments = () => {
            const formData = new FormData(document.getElementById('argumentForm'));
            const args = {};
            for (let [key, value] of formData.entries()) {
                if (value.trim()) {
                    args[key] = value.trim();
                }
            }
            document.body.removeChild(modal);
            resolve(args);
        };

        window.cancelArguments = () => {
            document.body.removeChild(modal);
            resolve(null);
        };
    });
}

// Custom Command Function
async function runCustomCommand() {
    const customCommandInput = document.getElementById("customCommandInput");
    const memoryFile = document.getElementById("memorySelect").value;

    // Validate inputs
    if (!memoryFile) {
        alert("Please select a memory dump file first");
        return;
    }

    const customSuffix = customCommandInput.value.trim();
    if (!customSuffix) {
        alert("Please enter a command suffix (e.g., 'windows.hivelist' or 'linux.pslist --pid 1234')");
        return;
    }

    // Extract the command and arguments from the input
    const parts = customSuffix.split(/\s+/);
    const command = parts[0];
    const args = {};

    // Parse command-line style arguments (--key value)
    for (let i = 1; i < parts.length; i++) {
        if (parts[i].startsWith('--')) {
            const argName = parts[i].substring(2);
            if (i + 1 < parts.length && !parts[i + 1].startsWith('--')) {
                args[argName] = parts[i + 1];
                i++; // Skip the value in next iteration
            } else {
                args[argName] = true; // Flag without value
            }
        }
    }

    // Determine OS type based on command prefix or use selected OS
    let osType = document.getElementById("osSelect").value;
    if (command.startsWith('windows.')) {
        osType = 'Windows';
    } else if (command.startsWith('linux.')) {
        osType = 'Linux';
    } else if (command.startsWith('mac.')) {
        osType = 'Mac';
    }

    if (!osType) {
        alert("Please select an operating system or use a command with OS prefix (e.g., 'windows.hivelist')");
        return;
    }

    try {
        console.log(`[DEBUG] Running custom command: ${command} with args:`, args);
        console.log(`[DEBUG] Memory file: ${memoryFile}, OS: ${osType}`);

        const response = await fetch("/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                memory_file: memoryFile,
                os_type: osType,
                command: command,
                arguments: args
            })
        });

        const result = await response.json();
        console.log(`[DEBUG] Custom command response:`, result);

        if (response.ok) {
            currentTaskId = result.task_id;
            console.log(`[DEBUG] Custom command started with ID: ${currentTaskId}`);
            alert(`Custom command started successfully! Command: "${customSuffix}"\nCheck the Results tab for output when complete.`);

            // Clear the input after successful submission
            customCommandInput.value = "";
        } else {
            console.error(`[ERROR] Failed to start custom command:`, result);
            alert(`Failed to start custom command: ${result.error}`);
        }
    } catch (error) {
        console.error(`[ERROR] Error running custom command:`, error);
        alert(`Error running custom command: ${error.message}`);
    }
}

// Add Enter key support for custom command input
document.addEventListener('DOMContentLoaded', function () {
    const customCommandInput = document.getElementById("customCommandInput");
    if (customCommandInput) {
        customCommandInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                runCustomCommand();
            }
        });
    }
});

// Task monitoring, execution status, and debug functions removed

async function refreshResults() {
    try {
        const response = await fetch("/files");
        const files = await response.json();

        const resultsList = document.getElementById("resultsList");
        resultsList.innerHTML = "";

        const resultFiles = files.filter(f => f.name.startsWith("volatility_") && f.name.endsWith(".txt"));
        const keyFiles = files.filter(f => f.name.toLowerCase().endsWith('.fvek'));

        resultFiles.forEach(file => {
            const fileItem = document.createElement("div");
            fileItem.className = "file-item";
            fileItem.innerHTML = `
                <div>
                    <strong>📄 ${file.name}</strong><br>
                    <small>${formatFileSize(file.size)} - ${new Date(file.modified).toLocaleString()}</small>
                </div>
                <div>
                    <button class="btn btn-info" onclick="viewTextFile('${file.name}')">👁️ View</button>
                    <button class="btn btn-success" onclick="downloadFile('${file.name}')">📥 Download</button>
                    <button class="btn btn-danger" onclick="deleteFile('${file.name}')">🗑️ Delete</button>
                </div>
            `;
            resultsList.appendChild(fileItem);
        });

        // List discovered FVEK key files
        keyFiles.forEach(file => {
            const fileItem = document.createElement("div");
            fileItem.className = "file-item";
            fileItem.innerHTML = `
                <div>
                    <strong>🔑 ${file.name}</strong><br>
                    <small>${formatFileSize(file.size)} - ${new Date(file.modified).toLocaleString()}</small>
                </div>
                <div>
                    <button class="btn btn-success" onclick="downloadFile('${file.name}')">📥 Download</button>
                    <button class="btn btn-danger" onclick="deleteFile('${file.name}')">🗑️ Delete</button>
                </div>
            `;
            resultsList.appendChild(fileItem);
        });

        if (resultFiles.length === 0 && keyFiles.length === 0) {
            resultsList.innerHTML = "<p>No analysis results found. Run some commands first!</p>";
        }
    } catch (error) {
        console.error("Error refreshing results:", error);
    }
}

async function viewTextFile(filename) {
    try {
        const response = await fetch(`/view-text/${filename}`);
        if (!response.ok) {
            throw new Error(`Failed to load file: ${response.status}`);
        }

        const content = await response.text();
        showTextReader(filename, content);

    } catch (error) {
        alert(`Error loading file: ${error.message}`);
    }
}

function showTextReader(filename, content) {
    const modal = document.createElement('div');
    modal.className = 'text-reader-modal';
    modal.innerHTML = `
        <div class="text-reader-content">
            <div class="text-reader-header">
                <h3>📄 ${filename}</h3>
                <div>
                    <button class="btn btn-success" onclick="downloadFile('${filename}')">📥 Download</button>
                    <button class="btn btn-secondary" onclick="closeTextReader()">✖️ Close</button>
                </div>
            </div>
            <div class="text-reader-body">
                <pre>${escapeHtml(content)}</pre>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // Add click outside to close
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeTextReader();
        }
    });

    // Store reference for closing
    window.currentTextReader = modal;

    window.closeTextReader = () => {
        if (window.currentTextReader) {
            document.body.removeChild(window.currentTextReader);
            window.currentTextReader = null;
        }
    };
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function downloadFile(filename) {
    window.open(`/download/${filename}`);
}

async function deleteFile(filename) {
    if (!confirm(`Delete ${filename}?`)) return;

    try {
        const response = await fetch(`/delete/${filename}`, { method: "DELETE" });
        const result = await response.json();

        if (response.ok) {
            refreshFiles();
            refreshResults();
            refreshMemorySelect();
        } else {
            alert(`Error: ${result.error}`);
        }
    } catch (error) {
        alert(`Error deleting file: ${error.message}`);
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Initialize
document.addEventListener("DOMContentLoaded", () => {
    initializeDragAndDrop();
    refreshFiles();
    // Task monitoring initialization removed
});
