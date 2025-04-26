# ZAP headless Optimized CLI Tool

An optimized OWASP ZAP automation tool that allows you to run security scans from the command line with enhanced performance and additional features.

## Features

- **Resource Optimization**: Configurable memory allocation and thread management to reduce resource consumption
- **Authentication Support**: Perform authenticated scans with username/password credentials
- **AJAX/Decibel Spider**: Option to use ZAP's AJAX/Decibel spider for JavaScript-heavy applications
- **Asynchronous Operations**: Uses Python's asyncio for more efficient execution
- **Parallel Report Generation**: Generate reports in multiple formats simultaneously
- **Memory Caching**: Uses LRU cache for frequently accessed operations
- **Better Logging**: Comprehensive logging with configurable verbosity
- **Cross-Platform Compatibility**: Tested on Windows and Kali Linux

## Installation

1. Ensure you have Python 3.6+ installed
2. Install OWASP ZAP: [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)
3. Install required Python packages:
   ```
   pip install asyncio
   ```

## Usage

Basic usage:

```bash
python zap-optimized-cli.py -t https://example.com
```

With authentication:

```bash
python zap-optimized-cli.py -t https://example.com --auth --auth-url https://example.com/login \
  --username user --password pass --username-field username --password-field password
```

With AJAX/Decibel spider:

```bash
python zap-optimized-cli.py -t https://example.com --decibel
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL to scan (required) |
| `-o, --output` | Output directory for reports (default: 'zap_report') |
| `-z, --zap-path` | Path to ZAP installation |
| `-p, --port` | Port for ZAP to listen on (default: 8080) |
| `-a, --api-key` | ZAP API key if required |
| `-s, --spider-timeout` | Spider timeout in minutes (default: 60) |
| `-c, --scan-timeout` | Scan timeout in minutes (default: 120) |
| `-m, --memory` | Memory allocation for ZAP (e.g., 1G, 2G) |
| `--auth` | Enable authentication |
| `--auth-url` | URL for authentication page |
| `--username` | Username for authentication |
| `--password` | Password for authentication |
| `--username-field` | HTML field name for username |
| `--password-field` | HTML field name for password |
| `--login-url` | URL to submit login form to |
| `--logged-in-regex` | Regex pattern to identify logged-in state |
| `--decibel` | Use AJAX/Decibel spider in addition to traditional spider |
| `--threads` | Number of threads for scanning (default: 2) |
| `--scan-policy` | Scan policy name to use |
| `--debug` | Enable debug output |

## Performance Considerations

- Use `--memory` to set appropriate memory allocation based on your system resources
- Adjust `--threads` based on your system's CPU capabilities and network bandwidth
- For large applications, increase timeout values with `-s` and `-c`

## Compatibility Notes

### Kali Linux / Python 3.11+

This tool has been specifically updated to work properly on Kali Linux with Python 3.11+. The following issues have been addressed:

1. **Event Loop Handling**: Fixed asyncio implementation to properly create and manage event loops, preventing the `asyncio/runners.py` errors that can occur in Python 3.11.

2. **Dictionary Parameter Handling**: Removed LRU caching from functions that accept dictionary parameters to prevent `TypeError: unhashable type: 'dict'` errors.

## Troubleshooting

If you encounter any issues running the tool:

1. **Permission Errors**: Ensure you have the necessary permissions to execute the script and access the ZAP binary.

2. **ZAP Not Found**: Use the `--zap-path` parameter to explicitly specify the location of your ZAP installation.

3. **Port Already in Use**: If port 8080 is already in use, specify a different port with the `--port` parameter.

4. **Memory Issues**: If ZAP crashes due to insufficient memory, try allocating more memory with the `--memory` parameter (e.g., `--memory 2G`).
