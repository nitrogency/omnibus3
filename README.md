# OSINT Omnibus
- Originally developed by [InQuest](https://www.inquest.net)
- Updated/rewritten by [nitrogency](https://github.com/nitrogency)

## Installation
Install the requirements using:
`pip install -r requirements.txt`
Then run the script with:
`python omnibus-cli.py`

That's it!

## Omnibus
A modular OSINT tool updated to work with Python3. Tested on Debian 12.

## Differences
- Rewritten to use a local JSON database, instead of MongoDB+Redis. Allows for simpler editing and installation, less dependencies.
- Removed all modules and created new ones. Focusing on less modules, but ones that have more functions. This allows for easier API key management and tool/code maintenance.
- As a consequence, removed most of the documentation, since it's now incompatible. WIP, will add in the future.
- Reworked the structure of the program, now everything is (mostly) part of one script, with only modules being separate. 

### Vocabulary
* Artifact:
  - An item to investigate
  - Artificats can be created in two ways:
    - Using the `new` command or by being discoverd through module execution
* Session:
  - Cache of artifacts created after starting the Omnibus CLI
  - Each artifact in a session is given an ID to quickly identify and retrieve the artifact from the cache
  - Commands can be executed against an artifact either by providing it's name or it's corresponding session ID
* Module:
  - Python script that performs some arbitirary OSINT task against an artifact
 
### Artifacts
Artifacts can be one of the following types:
* IPv4 address
* FQDN
* Bitcoin Address
* File Hash (MD5, SHA1, SHA256, SHA512)
* Keyword

### Sessions
Omnibus makes use of a feature called "sessions". Sessions are temporary caches created via Redis each time you start a CLI session. Every time you create an artifact, that artifacts name is added to the Session along with a numeric key that makes for easy retrieval, searching, and action against the related artifact.
For example if you're session held one item of "inquest.net", instead of needing to execute `virustotal inquest.net` you could also run `virustotal 1` and you would receive the same results. In fact, this works against any module or command that uses an artiface name as it's first argument.

