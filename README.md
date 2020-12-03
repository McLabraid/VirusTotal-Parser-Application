### Virustotal Parser Application 
Allows the user to submit files and webpages/IPs to be scanned by Virustotal and for the relevant reports to be requested from them.
This Application is entirely in GUI form.
In order to properly use this application, a user must insert their API key from Virustotal within the code.
It is suggested to pull the VT.img alongside this tool to allow it to work properly.

_**This tool was created during my Bachelor of Science(Honours) Degree at the Technological University of Dublin as an Application Security assignment.**_

## Requirements
This tool being a Python 3.x based tool, the following libraries are required in the running of this tool. 

virustotal-python==0.0.7
Pillow==7.0.0

These libraries are also listed within the requirements.txt and can be easily downloaded with the command.
```
pip install -r requirements.txt 
```

## GUI Interface 
This section will go over the GUI interface
![Main menu](https://github.com/McLabraid/VirusTotal-Parser-Application/blob/master/RMImages/Main.png)

1. Upload a file: A window is opened for the user to select an file to be analysed

2.	Get file Report: get the report for the file

3.	Upload URL: Input a URL to be inspected

4.	Get URL Report: Get report for the submitted URL

5. Malware Hash Report: Provide a SHA256 of a malware, and a report is returned.

