import platform
import os

def get_os_identifier():
    try:
        # General information
        os_name = platform.system()  # OS name: 'Windows', 'Linux', 'Darwin' (iOS/MacOS), or other
        os_version = platform.version()  # OS version
        os_release = platform.release()  # OS release
        architecture = platform.architecture()[0]  # '32bit' or '64bit'
        machine = platform.machine()  # Machine type: e.g., 'x86_64', 'arm64', etc.
        processor = platform.processor()  # Processor type

        # Handle specific mobile platforms
        if os_name == "Darwin":
            # Distinguish between macOS and iOS
            if "iPhone" in machine or "iPad" in machine:
                os_name = "iOS"
            else:
                os_name = "macOS"
        elif os_name == "Linux":
            # Android typically identifies as Linux, add specific checks
            if "android" in os_version.lower():
                os_name = "Android"
        
        # Build OS identifier
        os_identifier = (
            f"OS: {os_name}, "
            f"Version: {os_version}, "
            f"Release: {os_release}, "
            f"Architecture: {architecture}, "
            f"Machine: {machine}, "
            f"Processor: {processor}"
        )
    except Exception as e:
        os_identifier = f"Error identifying OS: {e}"
    
    return os_identifier

# Example usage
if __name__ == "__main__":
    identifier = get_os_identifier()
    print("OS Identifier:")
    print(identifier)
