#!/usr/bin/env python3
import os
import sys
import cmd2
import json
import datetime
import configparser
from typing import Optional, Dict, List, Any
from pathlib import Path
from lib.asciiart import show_banner
from lib.common import detect_type
import importlib

# Constants
MODULES_DIR = "lib/modules"
CONFIG_FILE = "etc/omnibus.conf"
DB_DIR = "db"
SESSIONS_DIR = os.path.join(DB_DIR, "sessions")

def ensure_directories():
    """Ensure required directories exist"""
    Path(DB_DIR).mkdir(exist_ok=True)
    Path(SESSIONS_DIR).mkdir(exist_ok=True)

class JsonDB:
    """JSON file-based database handler"""
    def __init__(self):
        ensure_directories()
        self.current_session = None
        self.session = {}

    def _get_session_path(self, session_name: str) -> str:
        """Get path for session directory"""
        return os.path.join(SESSIONS_DIR, session_name)

    def _get_session_file(self, session_name: str) -> str:
        """Get path for session info file"""
        return os.path.join(self._get_session_path(session_name), f"{session_name}.json")

    def _get_session_artifacts_dir(self, session_name: str) -> str:
        """Get path for session artifacts directory"""
        return os.path.join(self._get_session_path(session_name), "artifacts")

    def create_session(self, session_name: str) -> bool:
        """Create a new session"""
        session_path = self._get_session_path(session_name)
        session_file = self._get_session_file(session_name)
        artifacts_dir = self._get_session_artifacts_dir(session_name)

        if os.path.exists(session_path):
            return False
        
        # Create session directory structure
        Path(session_path).mkdir(exist_ok=True)
        Path(artifacts_dir).mkdir(exist_ok=True)
        
        self.session = {}
        self.current_session = session_name
        self._save_session()
        return True

    def select_session(self, session_name: str) -> bool:
        """Select an existing session"""
        session_file = self._get_session_file(session_name)
        if not os.path.exists(session_file):
            return False
        
        self.current_session = session_name
        self._load_session()
        return True

    def list_sessions(self) -> List[str]:
        """List all available sessions"""
        if not os.path.exists(SESSIONS_DIR):
            return []
        return [d for d in os.listdir(SESSIONS_DIR) 
                if os.path.isdir(os.path.join(SESSIONS_DIR, d))]

    def _load_session(self):
        """Load session from file"""
        if not self.current_session:
            self.session = {}
            return

        session_file = self._get_session_file(self.current_session)
        if os.path.exists(session_file):
            with open(session_file, 'r') as f:
                try:
                    session_data = json.load(f)
                    # Try to parse any JSON string values back to their original type
                    self.session = {}
                    for key, value in session_data.items():
                        try:
                            self.session[key] = json.loads(value)
                        except (json.JSONDecodeError, TypeError):
                            self.session[key] = value
                except json.JSONDecodeError:
                    self.session = {}
        else:
            self.session = {}

    def _save_session(self):
        """Save session to file"""
        if not self.current_session:
            return

        session_file = self._get_session_file(self.current_session)
        
        # Ensure all values are JSON serializable
        session_data = {}
        for key, value in self.session.items():
            if isinstance(value, (list, dict)):
                session_data[key] = json.dumps(value)
            else:
                session_data[key] = value

        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=4)

    def _get_artifact_path(self, artifact_type: str, name: str) -> str:
        """Get path for artifact file"""
        if not self.current_session:
            return ""

        # If name is a list, use the first element
        if isinstance(name, list):
            name = name[0]
        safe_name = name.replace('/', '_').replace('\\', '_')
        return os.path.join(self._get_session_artifacts_dir(self.current_session), 
                          f"{artifact_type}_{safe_name}.json")

    def insert_artifact(self, artifact_type: str, data: Dict) -> bool:
        """Insert a new artifact"""
        if not self.current_session:
            print("[!] No session selected. Create or select a session first.")
            return False

        try:
            # If name is a list, use the first element
            if isinstance(data['name'], list):
                data['name'] = data['name'][0]
            file_path = self._get_artifact_path(artifact_type, data['name'])
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Failed to save artifact: {str(e)}")
            return False

    def find_artifact(self, artifact_type: str, name: str) -> Optional[Dict]:
        """Find an artifact by type and name"""
        try:
            # If name is a list, use the first element
            if isinstance(name, list):
                name = name[0]
            file_path = self._get_artifact_path(artifact_type, name)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load artifact: {str(e)}")
        return None

    def exists(self, artifact_type: str, name: str) -> bool:
        """Check if artifact exists"""
        # If name is a list, use the first element
        if isinstance(name, list):
            name = name[0]
        file_path = self._get_artifact_path(artifact_type, name)
        return os.path.exists(file_path)

    def add_to_session(self, key: str, value: Any):
        """Add artifact to session"""
        if not self.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        # Convert any unhashable types to their string representation for storage
        if isinstance(value, (list, dict)):
            self.session[str(key)] = json.dumps(value)
        else:
            self.session[str(key)] = value
        self._save_session()

    def get_from_session(self, key: str) -> Optional[Any]:
        """Get artifact from session"""
        value = self.session.get(str(key))
        if value is None:
            return None
            
        # Try to parse JSON string back to original type
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    def list_session(self) -> Dict[str, str]:
        """List all artifacts in session"""
        return self.session

    def clear_session(self):
        """Clear current session"""
        if not self.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        # Clear session info
        self.session = {}
        self._save_session()

        # Remove all artifacts in session
        artifacts_dir = self._get_session_artifacts_dir(self.current_session)
        if os.path.exists(artifacts_dir):
            for file in os.listdir(artifacts_dir):
                os.remove(os.path.join(artifacts_dir, file))

    def delete_session(self, session_name: str) -> bool:
        """Delete a session and all its artifacts"""
        session_path = self._get_session_path(session_name)
        if not os.path.exists(session_path):
            return False
        
        try:
            # Delete all files in artifacts directory
            artifacts_dir = self._get_session_artifacts_dir(session_name)
            if os.path.exists(artifacts_dir):
                for file in os.listdir(artifacts_dir):
                    os.remove(os.path.join(artifacts_dir, file))
                os.rmdir(artifacts_dir)
            
            # Delete session file and directory
            session_file = self._get_session_file(session_name)
            if os.path.exists(session_file):
                os.remove(session_file)
            os.rmdir(session_path)
            
            # Clear current session if it was the deleted one
            if self.current_session == session_name:
                self.current_session = None
                self.session = {}
            
            return True
        except Exception as e:
            print(f"[!] Error deleting session: {str(e)}")
            return False

    def delete_artifact(self, artifact_type: str, name: str) -> bool:
        """Delete an artifact file"""
        file_path = self._get_artifact_path(artifact_type, name)
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False

    def remove_from_session(self, target_name: str) -> bool:
        """Remove artifact from session by name"""
        if not self.current_session:
            return False

        # Find and remove the artifact with matching name
        for key, value in list(self.session.items()):
            artifact_name = value
            if isinstance(value, str):
                try:
                    value_dict = json.loads(value)
                    if isinstance(value_dict, dict):
                        artifact_name = value_dict.get('name', value)
                except (json.JSONDecodeError, TypeError):
                    pass
            
            if artifact_name == target_name:
                del self.session[key]
                self._save_session()
                return True
        return False

class Artifact:
    """Artifact data model"""
    def __init__(self, name: str, artifact_type: Optional[str] = None):
        self.name = name
        self.type = artifact_type or self.detect_type(name)
        self.created = datetime.datetime.utcnow().isoformat()
        self.data = {}

    def detect_type(self, artifact: str) -> str:
        """Detect artifact type based on its characteristics"""
        if self.is_ip(artifact):
            return "ip"
        elif self.is_domain(artifact):
            return "domain"
        elif self.is_email(artifact):
            return "email"
        elif self.is_hash(artifact):
            return "hash"
        return "unknown"

    @staticmethod
    def is_ip(artifact: str) -> bool:
        """Check if artifact is an IP address"""
        parts = artifact.split('.')
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    @staticmethod
    def is_domain(artifact: str) -> bool:
        """Check if artifact is a domain name"""
        return '.' in artifact and not '@' in artifact

    @staticmethod
    def is_email(artifact: str) -> bool:
        """Check if artifact is an email address"""
        return '@' in artifact and '.' in artifact.split('@')[1]

    @staticmethod
    def is_hash(artifact: str) -> bool:
        """Check if artifact is a hash"""
        return all(c in '0123456789abcdefABCDEF' for c in artifact) and len(artifact) in [32, 40, 64]

    def to_dict(self) -> Dict:
        """Convert artifact to dictionary"""
        return {
            "name": self.name,
            "type": self.type,
            "created": self.created,
            "data": self.data
        }

class OmnibusShell(cmd2.Cmd):
    """Main Omnibus shell"""
    def __init__(self):
        super().__init__(
            persistent_history_file="~/.omnibus_history",
            persistent_history_length=1000
        )
        
        self.config = load_config(CONFIG_FILE)
        self.db = JsonDB()
        
        # Shell settings
        self.prompt = 'omnibus >> '
        self.intro = show_banner() + '\nWelcome to Omnibus! Type "help" for a list of commands.'
        
        # Enable debug mode
        self.debug = True
        
        # Module mapping
        self.modules = {
            'btc': ['blockchain'],
            'hash': ['virustotal', 'greyhat'],
            'ipv4': ['virustotal', 'viewdns'],
            'fqdn': ['virustotal', 'viewdns', 'crtsh'],
            'keyword': ['greyhat']
        }

    def _run_module(self, module: str, artifact: Optional[Dict]) -> Optional[Dict]:
        """Load Python library from modules directory and execute main function"""
        try:
            mod = importlib.import_module(f"lib.modules.{module}")
            return mod.main(artifact)
        except ImportError:
            print(f"[!] Module {module} not found")
            return None
        except Exception as e:
            print(f"[!] Error running module {module}: {str(e)}")
            return None

    def _show_module_help(self, module: str) -> None:
        """Show help information for a specific module"""
        try:
            mod = importlib.import_module(f"lib.modules.{module}")
            if hasattr(mod, 'info'):
                mod.info()
            else:
                print(f"[!] No help information available for module {module}")
        except ImportError:
            print(f"[!] Module {module} not found")
        except Exception as e:
            print(f"[!] Error showing help for module {module}: {str(e)}")

    def do_help(self, arg: str) -> None:
        """Show help information for commands or modules
        Usage: 
            help          - Show this general help message
            help <module> - Show help for a specific module
        
        Available commands:
            session  - Manage sessions (create/select/list/current)
            new     - Create a new artifact
            rm      - Remove an artifact
            modules - List available modules for an artifact
            run     - Run a specific module against an artifact
            machine - Run all available modules against an artifact
            ls      - List artifacts in current session
            wipe    - Clear current session
            quit    - Exit Omnibus
            help    - Show this help message"""
        
        if not arg:
            # Show general help
            print("\nOmnibus - OSINT Intelligence Framework")
            print("=" * 40)
            
            # Show command help
            print("\nCore Commands:")
            print("-" * 15)
            print("  session")
            print("    Usage: session <command> [args]")
            print("    Commands:")
            print("      create <name>  - Create a new session")
            print("      select <name>  - Select an existing session")
            print("      list          - List all available sessions")
            print("      current       - Show current session name")
            print("      delete <name> - Delete a session")
            
            print("\n  new")
            print("    Usage: new <artifact>")
            print("    Create a new artifact for investigation")
            
            print("\n  rm")
            print("    Usage: rm <artifact>")
            print("    Remove an artifact from both session and filesystem")
            
            print("\n  modules")
            print("    Usage: modules")
            print("    List all available modules and their compatible artifact types")
            
            print("\n  run")
            print("    Usage: run <module> [command] <artifact>")
            print("    Run a specific module against an artifact")
            
            print("\n  machine")
            print("    Usage: machine <artifact>")
            print("    Run all available modules against an artifact")
            
            print("\n  ls")
            print("    Usage: ls")
            print("    List artifacts in current session")
            
            print("\n  wipe")
            print("    Usage: wipe")
            print("    Clear current session")
            
            print("\n  quit")
            print("    Usage: quit")
            print("    Exit Omnibus")
            
            print("\nAvailable Artifact Types:")
            print("-" * 23)
            for artifact_type, modules in self.modules.items():
                print(f"  {artifact_type}: {', '.join(modules)}")
            
            print("\nFor module-specific help, type: help <module>")
            return
        
        # Show module-specific help
        self._show_module_help(arg.strip())

    def do_session(self, arg):
        """Session management commands
        Usage: 
            session create <n>  - Create a new session
            session select <n>  - Select an existing session
            session list          - List all available sessions
            session current       - Show current session name
            session delete <n>  - Delete a session"""
        args = arg.split()
        if not args:
            print("[!] Please specify a subcommand (create/select/list/current/delete)")
            return

        cmd = args[0].lower()
        if cmd == "create" and len(args) > 1:
            session_name = args[1]
            if self.db.create_session(session_name):
                print(f"[+] Created and selected new session: {session_name}")
                self.prompt = f'omnibus ({session_name}) >> '
            else:
                print(f"[!] Session '{session_name}' already exists")
        
        elif cmd == "select" and len(args) > 1:
            session_name = args[1]
            if self.db.select_session(session_name):
                print(f"[+] Selected session: {session_name}")
                self.prompt = f'omnibus ({session_name}) >> '
            else:
                print(f"[!] Session '{session_name}' not found")
        
        elif cmd == "list":
            sessions = self.db.list_sessions()
            if sessions:
                print("[*] Available sessions:")
                for session in sessions:
                    if session == self.db.current_session:
                        print(f"  - {session} (current)")
                    else:
                        print(f"  - {session}")
            else:
                print("[*] No sessions found")
        
        elif cmd == "current":
            if self.db.current_session:
                print(f"[*] Current session: {self.db.current_session}")
            else:
                print("[!] No session selected")

        elif cmd == "delete" and len(args) > 1:
            session_name = args[1]
            if session_name == self.db.current_session:
                print("[!] Cannot delete the current session. Switch to another session first.")
                return
            if self.db.delete_session(session_name):
                print(f"[+] Deleted session: {session_name}")
            else:
                print(f"[!] Session '{session_name}' not found")
        
        else:
            print("[!] Invalid command. Usage: session <create|select|list|current|delete> [name]")

    def do_new(self, arg: str) -> None:
        """Create a new artifact
        Usage: new <artifact>"""
        if not arg:
            print("[!] Please specify an artifact")
            return

        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        artifact_type = detect_type(arg)
        if artifact_type == 'unknown':
            print("[!] Unknown artifact type")
            return

        artifact = {
            'name': arg,
            'type': artifact_type,
            'subtype': '',
            'source': '',
            'parent': '',
            'created': datetime.datetime.utcnow().isoformat(),
            'children': [],
            'data': {}
        }

        if not self.db.exists(artifact_type, artifact['name']):
            self.db.insert_artifact(artifact_type, artifact)
            print(f"[+] Created new {artifact_type} artifact: {arg}")
            # Get next available ID for session
            session = self.db.list_session()
            next_id = str(len(session) + 1)
            self.db.add_to_session(next_id, arg)
            print(f"[+] Added to session with ID: {next_id}")
        else:
            print(f"[!] Artifact already exists: {arg}")

    def do_rm(self, arg: str) -> None:
        """Remove an artifact from both session and filesystem
        Usage: rm <artifact>"""
        if not arg:
            print("[!] Please specify an artifact")
            return

        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        # Get artifact details
        artifact = self._get_artifact(arg)
        if not artifact:
            print(f"[!] Artifact not found: {arg}")
            return

        # Delete from filesystem
        if self.db.delete_artifact(artifact['type'], artifact['name']):
            print(f"[+] Deleted artifact file: {artifact['name']}")
        
        # Remove from session
        if self.db.remove_from_session(artifact['name']):
            print(f"[+] Removed from session: {artifact['name']}")
        
        print("[+] Artifact deleted successfully")

    def do_modules(self, arg: str) -> None:
        """List all available modules and their compatible artifact types
        Usage: modules"""
        
        # Get all unique modules across all artifact types
        all_modules = sorted(set(module for modules in self.modules.values() for module in modules))
        
        print("\nAvailable modules:")
        for module in all_modules:
            # Show which artifact types can use this module
            compatible_types = [atype for atype, mods in self.modules.items() if module in mods]
            print(f"  - {module}")
            print(f"    Compatible with: {', '.join(compatible_types)}")
        print("\nTo run a module: run <module> <artifact>")

    def do_run(self, arg: str) -> None:
        """Run a specific module against an artifact
        Usage: run <module> [command] <artifact>"""
        args = arg.split()
        if len(args) < 2:
            print("[!] Please specify module and artifact")
            print("Usage: run <module> [command] <artifact>")
            return

        # Handle optional command parameter
        if len(args) == 3:
            module, command, artifact_name = args
        else:
            module, artifact_name = args
            command = None

        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        artifact = self._get_artifact(artifact_name)
        if not artifact:
            return

        # Check if module is valid for this artifact type
        artifact_type = artifact['type']
        if artifact_type not in self.modules or module not in self.modules[artifact_type]:
            print(f"[!] Module {module} is not supported for artifact type {artifact_type}")
            print("\nAvailable modules:")
            for m in sorted(self.modules.get(artifact_type, [])):
                print(f"  - {m}")
            return

        # Add command to artifact data if specified
        if command:
            if 'data' not in artifact:
                artifact['data'] = {}
            artifact['data']['command'] = command

        print(f"[*] Running {module} against {artifact_name}...")
        result = self._run_module(module, artifact)
        if result and module in result.get('data', {}):
            module_data = result['data'][module]
            if module_data is not None:
                self._process_result(artifact, result)
                print("[+] Module completed successfully. Data saved.")
            else:
                print(f"[!] No results found ({module})")
        else:
            print(f"[!] Failed to get module results ({module})")

    def do_machine(self, arg: str) -> None:
        """Run all available modules against an artifact
        Usage: machine <artifact>"""
        if not arg:
            print("[!] Please specify an artifact")
            return

        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        artifact = self._get_artifact(arg)
        if not artifact:
            return

        artifact_type = artifact['type']
        if artifact_type not in self.modules:
            print(f"[!] No modules available for artifact type: {artifact_type}")
            return

        # Initialize data dict if it doesn't exist
        if 'data' not in artifact:
            artifact['data'] = {}

        results = {}
        for module_name in self.modules[artifact_type]:
            print(f"[*] Running module: {module_name}")
            result = self._run_module(module_name, artifact)
            if result and isinstance(result.get('data', {}), dict):
                module_data = result['data'].get(module_name)
                if module_data is not None:
                    self._process_result(artifact, result)
                    results[module_name] = module_data
                else:
                    print(f"[!] No results found ({module_name})")
            else:
                print(f"[!] Failed to get module results ({module_name})")

        if results:
            print("\n[+] Machine results:")
            try:
                print(json.dumps(results, indent=2))
            except TypeError as e:
                print(f"[!] Error displaying results: {str(e)}")
                print("Raw results:", results)
        print("[+] Machine completed")

    def do_ls(self, _):
        """List artifacts in current session"""
        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        session = self.db.list_session()
        count = 0
        for key, value in session.items():
            print(f"[{key}] {value}")
            count += 1
        print(f"[*] Active Artifacts: {count}")

    def do_wipe(self, _):
        """Clear current session"""
        if not self.db.current_session:
            print("[!] No session selected. Create or select a session first.")
            return

        self.db.clear_session()
        print("[+] Session cleared")

    def do_quit(self, _):
        """Exit Omnibus"""
        print("[*] Goodbye!")
        return True

    def do_exit(self, _):
        """Exit Omnibus (alias for quit)"""
        return self.do_quit(_)

    def _get_artifact(self, artifact_name: str) -> Optional[Dict]:
        """Get artifact from database by name"""
        # First check if it's a session ID
        artifact_value = self.db.get_from_session(artifact_name)
        if artifact_value:
            artifact_name = artifact_value

        # Try each artifact type until we find it
        for artifact_type in ['ipv4', 'fqdn', 'hash', 'btc', 'keyword']:
            artifact = self.db.find_artifact(artifact_type, artifact_name)
            if artifact:
                return artifact

        # If not found, try detecting type as fallback
        artifact_type = detect_type(artifact_name)
        if artifact_type != 'unknown':
            artifact = self.db.find_artifact(artifact_type, artifact_name)
            if artifact:
                return artifact

        print(f"[!] Unable to find artifact: {artifact_name}")
        return None

    def _process_result(self, artifact: Dict, result: Dict) -> None:
        """Process and store module results"""
        # Initialize data dict if it doesn't exist
        if 'data' not in artifact:
            artifact['data'] = {}
        
        # Update artifact with new data
        if isinstance(result.get('data', {}), dict):
            artifact['data'].update(result.get('data', {}))
        
        # Process any child artifacts
        for child in result.get('children', []):
            child_artifact = {
                'name': child['name'],
                'type': child['type'],
                'subtype': child.get('subtype', ''),
                'source': child.get('source', ''),
                'parent': artifact['name'],
                'created': datetime.datetime.utcnow().isoformat(),
                'children': [],
                'data': {}
            }

            if not self.db.exists(child['type'], child['name']):
                self.db.insert_artifact(child['type'], child_artifact)

        # Update the original artifact
        self.db.insert_artifact(artifact['type'], artifact)

        if result.get('children'):
            print(f"[+] Created {len(result['children'])} child artifacts")

def load_config(config_path: str) -> configparser.ConfigParser:
    """Load configuration from file"""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def main():
    try:
        shell = OmnibusShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Caught keyboard interrupt, exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
