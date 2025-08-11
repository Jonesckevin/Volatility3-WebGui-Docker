import os
import subprocess
import json
import logging
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import threading
import time

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 65 * 1024 * 1024 * 1024  # 65GB max file size

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/volatility-app.log')
    ]
)

# Set up loggers for different levels
logger = logging.getLogger(__name__)
error_logger = logging.getLogger('error')
debug_logger = logging.getLogger('debug')

# Configure Flask app logger
app.logger.setLevel(logging.INFO)

# Log startup
logger.info("=== Volatility3 Web Interface Starting ===")
logger.info(f"Python version: {sys.version}")
logger.info(f"Flask application starting with debug mode")
logger.info(f"Upload folder: {UPLOAD_FOLDER if 'UPLOAD_FOLDER' in globals() else '/data'}")
logger.info("==========================================")

UPLOAD_FOLDER = "/data"
ALLOWED_EXTENSIONS = {".dd", ".raw", ".mem", ".dmp", ".img", ".vmem", ".bin"}

# Volatility commands organized by category - Complete list from vol --help
VOLATILITY_COMMANDS = {
    "General": {
        "Framework": {
            "banners.Banners": "Attempts to identify potential linux banners in an image",
            "configwriter.ConfigWriter": "Runs the automagics and both prints and outputs configuration in the output directory",
            "frameworkinfo.FrameworkInfo": "Plugin to list the various modular components of Volatility",
            "isfinfo.IsfInfo": "Determines information about the currently available ISF files, or a specific one",
            "layerwriter.LayerWriter": "Runs the automagics and writes out the primary layer produced by the stacker"
        },
        "Analysis": {
            "regexscan.RegExScan": "Scans kernel memory using RegEx patterns",
            "timeliner.Timeliner": "Runs all relevant plugins that provide time related information and orders the results by time",
            "vmscan.Vmscan": "Scans for Intel VT-d structures and generates VM volatility configs for them"
        }
    },
    "Windows": {
        "System Info": {
            "windows.info.Info": "Show OS & kernel details of the memory sample being analyzed",
            "windows.crashinfo.Crashinfo": "Lists the information from a Windows crash dump",
            "windows.statistics.Statistics": "Lists statistics about the memory space",
            "windows.kpcrs.KPCRs": "Print KPCR structure for each processor"
        },
        "Processes": {
            "windows.pslist.PsList": "Lists the processes present in a particular windows memory image",
            "windows.psscan.PsScan": "Scans for processes present in a particular windows memory image",
            "windows.pstree.PsTree": "Plugin for listing processes in a tree based on their parent process ID",
            "windows.psxview.PsXView": "Lists all processes found via four of the methods described in 'The Art of Memory Forensics'",
            "windows.cmdline.CmdLine": "Lists process command line arguments",
            "windows.envars.Envars": "Display process environment variables",
            "windows.handles.Handles": "Lists process open handles",
            "windows.privileges.Privs": "Lists process token privileges",
            "windows.hollowprocesses.HollowProcesses": "Lists hollowed processes",
            "windows.processghosting.ProcessGhosting": "Lists processes whose DeletePending bit is set or whose FILE_OBJECT is set to 0 or Vads that are DeleteOnClose",
            "windows.getsids.GetSIDs": "Print the SIDs owning each process"
        },
        "Memory": {
            "windows.malfind.Malfind": "Lists process memory ranges that potentially contain injected code",
            "windows.vadinfo.VadInfo": "Lists process memory ranges",
            "windows.vadwalk.VadWalk": "Walk the VAD tree",
            "windows.vadregexscan.VadRegExScan": "Scans all virtual memory areas for tasks using RegEx",
            "windows.memmap.Memmap": "Prints the memory map",
            "windows.bigpools.BigPools": "List big page pools",
            "windows.poolscanner.PoolScanner": "A generic pool scanner plugin",
            "windows.virtmap.VirtMap": "Lists virtual mapped sections"
        },
        "Network": {
            "windows.netscan.NetScan": "Scans for network objects present in a particular windows memory image",
            "windows.netstat.NetStat": "Traverses network tracking structures present in a particular windows memory image"
        },
        "Registry": {
            "windows.registry.hivelist.HiveList": "Lists the registry hives present in a particular memory image",
            "windows.registry.hivescan.HiveScan": "Scans for registry hives present in a particular windows memory image",
            "windows.registry.printkey.PrintKey": "Lists the registry keys under a hive or specific key value",
            "windows.registry.getcellroutine.GetCellRoutine": "Reports registry hives with a hooked GetCellRoutine handler",
            "windows.registry.userassist.UserAssist": "Print userassist registry keys and information",
            "windows.registry.certificates.Certificates": "Lists the certificates in the registry's Certificate Store",
            "windows.registry.amcache.Amcache": "Extract information on executed applications from the AmCache",
            "windows.registry.scheduled_tasks.ScheduledTasks": "Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times"
        },
        "Files": {
            "windows.filescan.FileScan": "Scans for file objects present in a particular windows memory image",
            "windows.dumpfiles.DumpFiles": "Dumps cached file contents from Windows memory samples",
            "windows.strings.Strings": "Reads output from the strings command and indicates which process(es) each string belongs to"
        },
        "Services": {
            "windows.svclist.SvcList": "Lists services contained with the services.exe doubly linked list of services",
            "windows.svcscan.SvcScan": "Scans for windows services",
            "windows.svcdiff.SvcDiff": "Compares services found through list walking versus scanning to find rootkits",
            "windows.getservicesids.GetServiceSIDs": "Lists process token sids",
            "windows.scheduled_tasks.ScheduledTasks": "Decodes scheduled task information from the Windows registry (deprecated)"
        },
        "Modules": {
            "windows.modules.Modules": "Lists the loaded kernel modules",
            "windows.modscan.ModScan": "Scans for modules present in a particular windows memory image",
            "windows.ldrmodules.LdrModules": "Lists the loaded modules in a particular windows memory image",
            "windows.drivermodule.DriverModule": "Determines if any loaded drivers were hidden by a rootkit",
            "windows.driverscan.DriverScan": "Scans for drivers present in a particular windows memory image",
            "windows.driverirp.DriverIrp": "List IRPs for drivers in a particular windows memory image",
            "windows.unloadedmodules.UnloadedModules": "Lists the unloaded kernel modules",
            "windows.dlllist.DllList": "Lists the loaded DLLs in a particular windows memory image"
        },
        "Threads": {
            "windows.threads.Threads": "Lists process threads",
            "windows.thrdscan.ThrdScan": "Scans for windows threads",
            "windows.suspended_threads.SuspendedThreads": "Enumerates suspended threads",
            "windows.suspicious_threads.SuspiciousThreads": "Lists suspicious userland process threads",
            "windows.orphan_kernel_threads.Threads": "Lists process threads"
        },
        "Security": {
            "windows.sessions.Sessions": "lists Processes with Session information extracted from Environmental Variables",
            "windows.skeleton_key_check.Skeleton_Key_Check": "Looks for signs of Skeleton Key malware",
            "windows.callbacks.Callbacks": "Lists kernel callbacks and notification routines",
            "windows.ssdt.SSDT": "Lists the system call table",
            "windows.iat.IAT": "Extract Import Address Table to list API (functions) used by a program contained in external libraries",
            "windows.unhooked_system_calls.unhooked_system_calls": "Looks for signs of Skeleton Key malware"
        },
        "Desktop": {
            "windows.desktops.Desktops": "Enumerates the Desktop instances of each Window Station",
            "windows.deskscan.DeskScan": "Scans for the Desktop instances of each Window Station",
            "windows.windowstations.WindowStations": "Scans for top level Windows Stations",
            "windows.windows.Windows": "Enumerates the Windows of Desktop instances"
        },
        "Executables": {
            "windows.pe_symbols.PESymbols": "Prints symbols in PE files in process and kernel memory",
            "windows.pedump.PEDump": "Allows extracting PE Files from a specific address in a specific address space",
            "windows.verinfo.VerInfo": "Lists version information from PE files"
        },
        "Console": {
            "windows.consoles.Consoles": "Looks for Windows console buffers",
            "windows.cmdscan.CmdScan": "Looks for Windows Command History lists"
        },
        "Miscellaneous": {
            "windows.devicetree.DeviceTree": "Listing tree based on drivers and attached devices in a particular windows memory image",
            "windows.joblinks.JobLinks": "Print process job link information",
            "windows.mutantscan.MutantScan": "Scans for mutexes present in a particular windows memory image",
            "windows.symlinkscan.SymlinkScan": "Scans for links present in a particular windows memory image",
            "windows.timers.Timers": "Print kernel timers and associated module DPCs",
            "windows.debugregisters.DebugRegisters": "Debug registers information",
            "windows.mbrscan.MBRScan": "Scans for and parses potential Master Boot Records (MBRs)",
            "windows.truecrypt.Passphrase": "TrueCrypt Cached Passphrase Finder",
            "windows.shimcachemem.ShimcacheMem": "Reads Shimcache entries from the ahcache.sys AVL tree",
            "windows.amcache.Amcache": "Extract information on executed applications from the AmCache (deprecated)"
        }
    },
    "Linux": {
        "System": {
            "linux.bash.Bash": "Recovers bash command history from memory",
            "linux.boottime.Boottime": "Shows the time the system was started",
            "linux.envars.Envars": "Lists processes with their environment variables",
            "linux.iomem.IOMem": "Generates an output similar to /proc/iomem on a running system",
            "linux.kmsg.Kmsg": "Kernel log buffer reader",
            "linux.vmcoreinfo.VMCoreInfo": "Enumerate VMCoreInfo tables"
        },
        "Processes": {
            "linux.pslist.PsList": "Lists the processes present in a particular linux memory image",
            "linux.psscan.PsScan": "Scans for processes present in a particular linux image",
            "linux.pstree.PsTree": "Plugin for listing processes in a tree based on their parent process ID",
            "linux.psaux.PsAux": "Lists processes with their command line arguments",
            "linux.pscallstack.PsCallStack": "Enumerates the call stack of each task",
            "linux.kthreads.Kthreads": "Enumerates kthread functions",
            "linux.pidhashtable.PIDHashTable": "Enumerates processes through the PID hash table"
        },
        "Memory": {
            "linux.proc.Maps": "Lists all memory maps for all processes",
            "linux.malfind.Malfind": "Lists process memory ranges that potentially contain injected code",
            "linux.vmaregexscan.VmaRegExScan": "Scans all virtual memory areas for tasks using RegEx",
            "linux.capabilities.Capabilities": "Lists process capabilities"
        },
        "Network": {
            "linux.ip.Addr": "Lists network interface information for all devices",
            "linux.ip.Link": "Lists information about network interfaces similar to `ip link show`",
            "linux.sockstat.Sockstat": "Lists all network connections for all processes",
            "linux.netfilter.Netfilter": "Lists Netfilter hooks"
        },
        "Modules": {
            "linux.lsmod.Lsmod": "Lists loaded kernel modules",
            "linux.hidden_modules.Hidden_modules": "Carves memory to find hidden kernel modules",
            "linux.modxview.Modxview": "Centralize lsmod, check_modules and hidden_modules results to efficiently spot modules presence and taints",
            "linux.module_extract.ModuleExtract": "Recreates an ELF file from a specific address in the kernel"
        },
        "Files": {
            "linux.elfs.Elfs": "Lists all memory mapped ELF files for all processes",
            "linux.library_list.LibraryList": "Enumerate libraries loaded into processes",
            "linux.lsof.Lsof": "Lists open files for each processes",
            "linux.mountinfo.MountInfo": "Lists mount points on processes mount namespaces",
            "linux.pagecache.Files": "Lists files from memory",
            "linux.pagecache.InodePages": "Lists and recovers cached inode pages",
            "linux.pagecache.RecoverFs": "Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball"
        },
        "Security": {
            "linux.check_afinfo.Check_afinfo": "Verifies the operation function pointers of network protocols",
            "linux.check_creds.Check_creds": "Checks if any processes are sharing credential structures",
            "linux.check_idt.Check_idt": "Checks if the IDT has been altered",
            "linux.check_modules.Check_modules": "Compares module list to sysfs info, if available",
            "linux.check_syscall.Check_syscall": "Check system call table for hooks",
            "linux.ptrace.Ptrace": "Enumerates ptrace's tracer and tracee tasks"
        },
        "Tracing": {
            "linux.tracing.ftrace.CheckFtrace": "Detect ftrace hooking",
            "linux.tracing.perf_events.PerfEvents": "Lists performance events for each process",
            "linux.tracing.tracepoints.CheckTracepoints": "Detect tracepoints hooking",
            "linux.ebpf.EBPF": "Enumerate eBPF programs"
        },
        "Miscellaneous": {
            "linux.graphics.fbdev.Fbdev": "Extract framebuffers from the fbdev graphics subsystem",
            "linux.keyboard_notifiers.Keyboard_notifiers": "Parses the keyboard notifier call chain",
            "linux.kallsyms.Kallsyms": "Kallsyms symbols enumeration plugin",
            "linux.tty_check.tty_check": "Checks tty devices for hooks"
        }
    },
    "Mac": {
        "System": {
            "mac.bash.Bash": "Recovers bash command history from memory",
            "mac.dmesg.Dmesg": "Prints the kernel log buffer",
            "mac.ifconfig.Ifconfig": "Lists network interface information for all devices",
            "mac.mount.Mount": "A module containing a collection of plugins that produce data typically found in Mac's mount command",
            "mac.netstat.Netstat": "Lists all network connections for all processes"
        },
        "Processes": {
            "mac.pslist.PsList": "Lists the processes present in a particular mac memory image",
            "mac.pstree.PsTree": "Plugin for listing processes in a tree based on their parent process ID",
            "mac.psaux.Psaux": "Recovers program command line arguments",
            "mac.proc_maps.Maps": "Lists process memory ranges that potentially contain injected code"
        },
        "Security": {
            "mac.check_syscall.Check_syscall": "Check system call table for hooks",
            "mac.check_sysctl.Check_sysctl": "Check sysctl handlers for hooks",
            "mac.check_trap_table.Check_trap_table": "Check mach trap table for hooks",
            "mac.kauth_listeners.Kauth_listeners": "Lists kauth listeners and their status",
            "mac.kauth_scopes.Kauth_scopes": "Lists kauth scopes and their status",
            "mac.trustedbsd.Trustedbsd": "Checks for malicious trustedbsd modules",
            "mac.socket_filters.Socket_filters": "Enumerates kernel socket filters"
        },
        "Files": {
            "mac.list_files.List_Files": "Lists all open file descriptors for all processes",
            "mac.lsof.Lsof": "Lists all open file descriptors for all processes",
            "mac.vfsevents.VFSevents": "Lists processes that are filtering file system events"
        },
        "Modules": {
            "mac.lsmod.Lsmod": "Lists loaded kernel modules"
        },
        "Memory": {
            "mac.malfind.Malfind": "Lists process memory ranges that potentially contain injected code"
        },
        "Miscellaneous": {
            "mac.kevents.Kevents": "Lists event handlers registered by processes",
            "mac.timers.Timers": "Check for malicious kernel timers"
        }
    }
}

# Plugins that require additional arguments
PLUGINS_WITH_ARGS = {
    'windows.registry.printkey.PrintKey': {'key': 'Registry key path (required)'},
    'windows.vadregexscan.VadRegExScan': {'pattern': 'Regex pattern (required)'},
    'linux.vmaregexscan.VmaRegExScan': {'pattern': 'Regex pattern (required)'},
    'regexscan.RegExScan': {'pattern': 'Regex pattern (required)'},
    'windows.strings.Strings': {'string': 'String to search (optional)'},
    'windows.dumpfiles.DumpFiles': {'pid': 'Process ID (optional)', 'physaddr': 'Physical address (optional)'},
    'windows.pedump.PEDump': {'pid': 'Process ID (optional)', 'base': 'Base address (optional)'},
    'windows.vadinfo.VadInfo': {'pid': 'Process ID (optional)'},
    'windows.handles.Handles': {'pid': 'Process ID (optional)'},
    'windows.cmdline.CmdLine': {'pid': 'Process ID (optional)'},
    'windows.dlllist.DllList': {'pid': 'Process ID (optional)'},
    'windows.envars.Envars': {'pid': 'Process ID (optional)'},
    'windows.privileges.Privs': {'pid': 'Process ID (optional)'},
    'linux.proc.Maps': {'pid': 'Process ID (optional)'},
    'linux.psaux.PsAux': {'pid': 'Process ID (optional)'},
    'linux.lsof.Lsof': {'pid': 'Process ID (optional)'},
    'timeliner.Timeliner': {'output': 'Output format (optional): json, csv, body'},
    'layerwriter.LayerWriter': {'output': 'Output file path (required)'}
}

# Store running tasks
running_tasks = {}

def run_volatility_command(memory_file, os_type, command, arguments, task_id):
    """Run volatility command in background"""
    try:
        logger.info(f"Starting task {task_id}: {command} with args: {arguments}")
        debug_logger.debug(f"Task details - Memory file: {memory_file}, OS: {os_type}")
        
        # Update task status
        running_tasks[task_id]["status"] = "running"
        running_tasks[task_id]["start_time"] = datetime.now().isoformat()
        
        # Prepare command
        vol_cmd = f"/opt/volatility-env/bin/vol"
        
        # Handle different plugin formats - ensure we always use the full plugin name
        if command.startswith(('windows.', 'linux.', 'mac.')):
            # Plugin already has the OS prefix
            full_command = f"{vol_cmd} -f {memory_file} {command}"
        elif command in ['banners.Banners', 'configwriter.ConfigWriter', 'frameworkinfo.FrameworkInfo', 
                        'isfinfo.IsfInfo', 'layerwriter.LayerWriter', 'regexscan.RegExScan', 
                        'timeliner.Timeliner', 'vmscan.Vmscan']:
            # General plugins without OS prefix
            full_command = f"{vol_cmd} -f {memory_file} {command}"
        else:
            # Legacy format - add OS prefix if needed
            # Ensure we use the full command name to avoid ambiguity
            if os_type.lower() == "windows":
                full_command = f"{vol_cmd} -f {memory_file} windows.{command}"
            elif os_type.lower() == "linux":
                full_command = f"{vol_cmd} -f {memory_file} linux.{command}"
            elif os_type.lower() == "mac":
                full_command = f"{vol_cmd} -f {memory_file} mac.{command}"
            else:
                full_command = f"{vol_cmd} -f {memory_file} {command}"
        
        # Add arguments if provided
        if arguments:
            for arg_name, arg_value in arguments.items():
                if arg_value and str(arg_value).strip():
                    full_command += f" --{arg_name} '{arg_value}'"
        
        logger.info(f"Executing command: {full_command}")
        debug_logger.debug(f"Full command path: {full_command}")
        
        # Log the exact command being executed to task data
        running_tasks[task_id]["command_executed"] = full_command
        
        # Run command
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=3600)
        
        logger.info(f"Command completed: {full_command} (return code: {result.returncode})")
        
        # Save output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        memory_file_name = os.path.basename(memory_file).split('.')[0]
        
        # Add batch indicator if this is a batch task
        batch_indicator = "_batch" if running_tasks[task_id].get("batch", False) else ""
        
        output_file = f"/data/volatility_{command.replace('.', '_')}_{memory_file_name}_{timestamp}{batch_indicator}.txt"
        
        with open(output_file, "w") as f:
            f.write(f"Command: {full_command}\n")
            f.write(f"Execution Time: {datetime.now()}\n")
            f.write(f"Return Code: {result.returncode}\n")
            f.write("=" * 50 + "\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\nERRORS:\n")
                f.write(result.stderr)
        
        # Determine status based on return code and content
        if result.returncode == 0:
            status = "completed"
            logger.info(f"Task {task_id} completed successfully. Command: {full_command}")
        else:
            status = "failed"
            error_logger.error(f"Task {task_id} failed with return code {result.returncode}. Command: {full_command}")
            if result.stderr:
                error_logger.error(f"Error output: {result.stderr}")
        
        # Update task with results
        running_tasks[task_id].update({
            "status": status,
            "end_time": datetime.now().isoformat(),
            "output": result.stdout,
            "error": result.stderr,
            "output_file": output_file,
            "return_code": result.returncode,
            "command_executed": full_command,
            "live_output": result.stdout + ("\n\nERRORS:\n" + result.stderr if result.stderr else "")
        })
        
    except subprocess.TimeoutExpired:
        error_logger.error(f"Task {task_id} timed out after 1 hour. Command: {running_tasks[task_id].get('command_executed', 'Unknown')}")
        running_tasks[task_id].update({
            "status": "timeout",
            "end_time": datetime.now().isoformat(),
            "error": "Command timed out after 1 hour",
            "live_output": "❌ Command execution timed out after 1 hour"
        })
    except Exception as e:
        error_logger.error(f"Task {task_id} failed with exception: {str(e)}. Command: {running_tasks[task_id].get('command_executed', 'Unknown')}")
        running_tasks[task_id].update({
            "status": "error",
            "end_time": datetime.now().isoformat(),
            "error": str(e),
            "live_output": f"❌ Execution error: {str(e)}"
        })

@app.route("/")
def index():
    logger.info("Home page accessed")
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    logger.info("File upload request received")
    if "file" not in request.files:
        error_logger.error("Upload request missing file")
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        error_logger.error("Upload request with empty filename")
        return jsonify({"error": "No file selected"}), 400
    
    # Check file extension
    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()
    
    if file_ext not in ALLOWED_EXTENSIONS:
        error_logger.error(f"Invalid file extension: {file_ext}")
        return jsonify({"error": f"File type {file_ext} not allowed"}), 400
    
    # Save file
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    logger.info(f"File uploaded successfully: {filename} ({file_ext})")
    return jsonify({"message": "File uploaded successfully", "filename": filename})

@app.route("/files")
def list_files():
    files = []
    for f in os.listdir(UPLOAD_FOLDER):
        filepath = os.path.join(UPLOAD_FOLDER, f)
        if os.path.isfile(filepath):
            stat = os.stat(filepath)
            files.append({
                "name": f,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
    return jsonify(files)

@app.route("/commands")
def get_commands():
    return jsonify(VOLATILITY_COMMANDS)

@app.route("/plugin-args/<plugin_name>")
def get_plugin_args(plugin_name):
    """Get arguments for a specific plugin"""
    args = PLUGINS_WITH_ARGS.get(plugin_name, {})
    return jsonify(args)

@app.route("/run", methods=["POST"])
def run_command():
    data = request.json
    memory_file = data.get("memory_file")
    os_type = data.get("os_type")
    command = data.get("command")
    arguments = data.get("arguments", {})
    
    logger.info(f"Command execution request: {command} on {memory_file} ({os_type})")
    logger.info(f"Raw command received: '{command}', OS type: '{os_type}'")
    debug_logger.debug(f"Command arguments: {arguments}")
    debug_logger.debug(f"Full request data: {data}")
    
    if not all([memory_file, os_type, command]):
        error_logger.error("Missing required parameters in command request")
        return jsonify({"error": "Missing required parameters"}), 400
    
    # Check if file exists
    full_path = os.path.join(UPLOAD_FOLDER, memory_file)
    if not os.path.exists(full_path):
        error_logger.error(f"Memory file not found: {memory_file}")
        return jsonify({"error": "Memory file not found"}), 404
    
    # Create task ID
    task_id = f"{int(time.time())}_{command.replace('.', '_')}"
    logger.info(f"Creating task {task_id} for command: {command}")
    
    # Initialize task
    running_tasks[task_id] = {
        "id": task_id,
        "memory_file": memory_file,
        "os_type": os_type,
        "command": command,
        "arguments": arguments,
        "status": "queued",
        "created": datetime.now().isoformat()
    }
    
    debug_logger.debug(f"Task {task_id} initialized: {running_tasks[task_id]}")
    
    # Start background task
    thread = threading.Thread(target=run_volatility_command, 
                            args=(full_path, os_type, command, arguments, task_id))
    thread.daemon = True
    thread.start()
    
    logger.info(f"Background thread started for task {task_id}")
    return jsonify({"task_id": task_id, "status": "started"})

# Status monitoring, live output, debug, and task management endpoints removed

@app.route("/help")
def help_documentation():
    """Serve the help documentation with corrected CSS paths"""
    help_path = os.path.join(app.static_folder, "help", "index.html")
    if os.path.exists(help_path):
        with open(help_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
            
        # Fix relative CSS and JS paths to work with our routing
        html_content = html_content.replace('href="_static/', 'href="/help/_static/')
        html_content = html_content.replace('src="_static/', 'src="/help/_static/')
        
        # Return the modified HTML with proper Content-Type
        return html_content, 200, {'Content-Type': 'text/html; charset=utf-8'}
    else:
        return "<h1>Help documentation not available</h1><p>The documentation could not be loaded. Please check the Docker build process.</p>", 404

@app.route("/help/<path:filename>")
def help_files(filename):
    """Serve help documentation files"""
    help_dir = os.path.join(app.static_folder, "help")
    file_path = os.path.join(help_dir, filename)
    
    # Security check - ensure the file is within the help directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(help_dir)):
        return "Access denied", 403
    
    if os.path.exists(file_path):
        # Set appropriate MIME type for CSS files
        if filename.endswith('.css'):
            return send_file(file_path, mimetype='text/css')
        elif filename.endswith('.js'):
            return send_file(file_path, mimetype='application/javascript')
        elif filename.endswith('.png'):
            return send_file(file_path, mimetype='image/png')
        elif filename.endswith('.ico'):
            return send_file(file_path, mimetype='image/x-icon')
        else:
            return send_file(file_path)
    else:
        return f"Help file not found: {filename}", 404

@app.route("/view-text/<filename>")
def view_text_file(filename):
    """Serve text file content for viewing"""
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download/<filename>")
def download_file(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    return send_file(filepath, as_attachment=True)

@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    logger.info(f"File deletion request: {filename}")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(filepath):
        error_logger.error(f"File not found for deletion: {filename}")
        return jsonify({"error": "File not found"}), 404
    
    try:
        os.remove(filepath)
        logger.info(f"File deleted successfully: {filename}")
        return jsonify({"message": "File deleted successfully"})
    except Exception as e:
        error_logger.error(f"Error deleting file {filename}: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info("Starting Flask development server")
    app.run(host="0.0.0.0", port=5000, debug=True)
