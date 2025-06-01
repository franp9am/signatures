Personal experiments with PDF document's

## Bulk signing

E-signs all documents in a folder with the pyHanko package.
If LTA (long-term-validity) is required, we need a qualified time-stamp.
Sectigo seems to be offering this for free at present time.


## Basic instructions


### Dependencies
* get python and pip or uv
* clone this repository, for instance `git clone https://github.com/franp9am/signatures.git`
* copy `config_template.ini` to `config.ini` and complete the path to the .p12 file with your encrypted private key
* install python dependencies with `pip install -e .` (slow) or `uv pip install -e .` (fast)
  
### Folders with pdf's

* copy all pdfs you want to sign to `unsigned/` folder. Alternatively, change the `config.ini` if other folder should be used
* signed documents will be in `signed` folder


### Usage

* `python bulk-sign -h` prints help
* `python bulk-sign -pp my_p12_file_password` signs all documents with the B-B validity level: pdf's are legally valid as long as your certificate is valid
* `python bulk-sign -pp my_p12_file_password -l` signs all documents with the B-LTA validity level: pdf's are valid forever or untill crypto algorithms are broken
* (TODO: support for B-LT level which only requires one time-stamps, not two)

### Qualified timestamps provider

For the LTA long-term validity, a qualified timestamp is needed. Current code is configured to call the "http://timestamp.sectigo.com/qualified" endpoint which seems to work for free and without registration.
It is eIDAS qualified and valid in EU.

It is not clear what are the rate limits, if there are some. Please use modestly. No guarantees.


## Great validation site

https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
