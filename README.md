Personal experiments with PDF document's

## Bulk signing

E-signs all documents in a folder with the pyHanko package.

## Basic instructions

### Dependencies
* get python and pip or uv
* clone this repository, for instance `git clone https://github.com/franp9am/signatures.git`
* copy `config_template.ini` to `config.ini` and complete the path to the .p12 file with your encrypted private key
* install python dependencies with `pip install .` (slow) or `uv pip install .` (fast)
  
### Folders with pdf's

* copy all pdfs you want to sign to `unsigned/` folder. Alternatively, change the `config.ini` if other folder should be used
* signed documents will be in `signed` folder


### Usage

* `python bulk-sign.py -h` prints help
* `python bulk-sign.py -pp my_p12_file_password` signs all documents with the B-B validity level: pdf's are legally valid as long as your certificate is valid
* `python bulk-sign.py -pp my_p12_file_password -lt` signs all documents with the B-LT validity level: pdf's are valid even after your certificate expires

### Qualified timestamps provider

For the long-term validity, a qualified timestamp is needed. Current code is configured to call the "sectigo" endpoint which seems to work for free for testing purposes.
It is eIDAS qualified and valid in EU.

It is not clear what are the rate limits or how long it will work. Please use modestly.


## Great validation site

https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation


## Windows setup for non-pythonists

* Open windows powershell
* winget install --id Git.Git -e --source winget
  * restart powershell if necessary
* winget install --id Python.Python.3.11 -e --source winget
  * restart powerhell if necessary
* git clone https://github.com/franp9am/signatures.git
* cd signatures
* cp config_template.ini config.ini
* edit config.ini, get path to your credentials file
* python -m venv venv
* .\venv\Scripts\Activate.ps1
* pip install .
* python bulk-sign.py -h


## Todo

* retrials
* more cli commands
* disable copy-pasting or pdf-printing, if required
