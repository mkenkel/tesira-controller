# Copilot Instructions for tesira-controller

## Overview
The `tesira-controller` project is a Python application designed to control Tesira devices via RS-232 over SSH. The project is structured for simplicity, with the main application logic in `app.py` and configuration in `commands.json`.

## Key Files
- **`app.py`**: The main entry point of the application. Contains the core logic for interacting with Tesira devices.
- **`commands.json`**: A JSON file defining the commands that can be sent to Tesira devices. This file is critical for understanding the supported operations.
- **`requirements.txt`**: Lists the Python dependencies required to run the application.
- **`README.md`**: Provides a brief overview of the project.

## Architecture
The application follows a straightforward architecture:
1. **Command Parsing**: Commands are defined in `commands.json` and loaded into the application.
2. **Device Communication**: Communication with Tesira devices is handled via RS-232 over an SSH connection.
3. **Execution Flow**: The main logic in `app.py` orchestrates the loading of commands, establishing SSH connections, and sending RS-232 commands.

## Developer Workflows
### Setting Up the Environment
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
Run the main script:
```bash
python app.py
```

### Debugging
- Use print statements or a debugger to trace issues in `app.py`.
- Ensure the `commands.json` file is correctly formatted and contains valid commands.

## Project-Specific Conventions
- **Command Definitions**: All commands must be defined in `commands.json`. Follow the existing structure when adding new commands.
- **Error Handling**: Ensure that SSH connection errors and RS-232 communication issues are logged clearly.

## External Dependencies
- **SSH Library**: The application relies on an SSH library (e.g., `paramiko`) to establish connections.
- **JSON Parsing**: Commands are loaded from `commands.json` using Python's built-in JSON library.

## Examples
### Adding a New Command
1. Open `commands.json`.
2. Add a new command in the following format:
   ```json
   {
       "command_name": "description",
       "command_string": "RS-232 command here"
   }
   ```
3. Save the file and restart the application.

### Debugging SSH Issues
- Verify the SSH credentials and connection details in `app.py`.
- Test the SSH connection manually using an SSH client to ensure the device is reachable.

## Notes
- This project assumes familiarity with RS-232 communication and SSH protocols.
- Contributions should include tests for new features or commands where applicable.
