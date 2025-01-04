# ThreadHijacking
A tool for performing thread hijacking in target processes on Windows for testing and research purposes.

## Requirements
- Visual Studio 2019 or higher
- Windows SDK (for access to Windows APIs)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/nffdev/ThreadHijacking.git
   ```
2. Open the project in Visual Studio.
3. Compile the project using the `Release` or `Debug` configuration.

## Use

1. **Compile the application:**
   - Open the project in Visual Studio.
   - Select either the `Debug` or `Release` configuration and build the project.

2. **Run the application:**
   - Execute the compiled binary.

3. **Provide the required inputs:**
   - Enter the **PID (Process ID)** of the target process when prompted.  
     Example: If targeting `notepad.exe`, you can find its PID using the Task Manager or any process enumeration tool.

4. **Execution:**
   - The tool will:
     - Locate a thread in the target process.
     - Suspend the thread to safely manipulate its execution context.
     - Allocate memory in the target process and inject the shellcode.
     - Overwrite the thread's execution context to point to the injected shellcode.
     - Resume the thread to execute the shellcode.

5. **Output:**
   - The tool will log key details (e.g., allocated memory addresses, thread handles) and confirm if the operation was successful.
  
## Technical Details

- **CreateToolhelp32Snapshot**: Captures a snapshot of all threads or processes in the system, allowing the tool to enumerate threads associated with the target process.
- **Thread32Next**: Iterates through the list of threads obtained from the snapshot to locate a thread belonging to the target process.
- **OpenThread**: Opens a handle to a specific thread in the target process, granting access for context modification and memory injection.
- **SuspendThread**: Temporarily suspends the execution of the target thread, ensuring safe manipulation of its context.
- **GetThreadContext**: Retrieves the current context (e.g., instruction pointer) of the suspended thread for modification.
- **VirtualAllocEx**: Allocates memory in the target process for storing the shellcode to be executed.
- **WriteProcessMemory**: Writes the shellcode into the allocated memory of the target process.
- **SetThreadContext**: Updates the thread's execution context, specifically setting the instruction pointer to point to the injected shellcode.
- **ResumeThread**: Resumes the execution of the modified thread, allowing it to execute the injected shellcode.
- **Shellcode Execution**: The injected shellcode executes in the context of the target process, allowing arbitrary payload execution.
- **LogHex**: Utility function to log memory addresses in a human-readable hexadecimal format.

## Resources

- [Official Microsoft documentation on Windows APIs](https://docs.microsoft.com/en-us/windows/win32/)

## Notes:
- The tool uses **CONTEXT_FULL** to access and modify all registers in the thread's context.
- Memory is allocated with **PAGE_EXECUTE_READWRITE** permissions to ensure the shellcode is executable.
- Proper error handling is implemented to log issues during each step of the injection process.

## Demo

![Demo](https://raw.githubusercontent.com/nffdev/ThreadHijacking/main/demo.gif)
