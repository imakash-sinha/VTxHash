# VTxHash - VirusTotal Hash Scanner

VTxHash is a Python-based tool that checks file hashes against the VirusTotal database to identify potential threats. It supports **bulk scanning** and exports structured results in **CSV and TXT** formats.

## Features

- **Bulk Hash Scanning** – Process multiple hashes at once.
- **VirusTotal API Integration** – Uses VirusTotal’s API to fetch scan results.
- **Hash Type Detection** – Automatically identifies **MD5, SHA-1, and SHA-256** hashes.
- **Structured Output** – Saves results in **CSV (comma-separated)** and **TXT (tab-separated)** formats.
- **Error Handling** – Gracefully handles missing hashes, API failures, and rate limits.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/imakash-sinha/VTxHash.git
cd VTxHash
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key

Edit `VTxHash.py` and replace `<YOUR API KEY>` with your **VirusTotal API key**.

## Usage

Run the script with an input file containing hashes, specifying output files for CSV and TXT:

```bash
python VTxHash.py hash.txt -o results.csv -t results.txt
```

### Command-line Arguments

| Argument | Description |
| --- | --- |
| `hash.txt` | Input file containing one hash per line |
| `-o results.csv` | Output CSV file for structured results |
| `-t results.txt` | Output TXT file for tabular format |

## Example

### Input (`hash.txt`):

```bash
44d88612fea8a8f36de82e1278abb02f
99017f6eebbac24f351415dd410d522d
```

### Execution:

```bash
python VTxHash.py hash.txt -o scan_results.csv -t scan_results.txt
```

### CSV Output (`scan_results.csv`):

```mathematica
Link,Hash Type,File Name,File Type,Undetected,Detected_Suspicious,Detected_Malicious,Threat Label,Tags
https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f,MD5,eicar.com,DOS Executable,50,2,5,Trojan,executable,testfile
https://www.virustotal.com/gui/file/99017f6eebbac24f351415dd410d522d,MD5,Unknown,Unknown,60,0,1,N/A,N/A
```

### TXT Output (`scan_results.txt`):

```mathematica
Link                                            Hash Type    File Name   File Type   Undetected   Suspicious   Malicious   Threat Label       Tags
------------------------------------------------------------------------------------------------------------------------------
https://www.virustotal.com/gui/file/44d88612f   MD5         eicar.com   DOS Executable      50          2          5        Trojan      executable,testfile
https://www.virustotal.com/gui/file/99017f6e    MD5         Unknown     Unknown             60          0          1        N/A         N/A
```

## Notes & Limitations

- **VirusTotal API Key Required** – You must have a VirusTotal API key.
- **Rate Limits Apply** – The free API has a limit of **4 requests per minute**.
- **No File Uploading** – This tool only checks **existing hash records** on VirusTotal.

## References

- Get a VirusTotal API Key
- VirusTotal API Documentation

## Contributions

Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.
