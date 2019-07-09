<h1 align="center">
  IFEO Debugger
  <br>
</h1>

<h4 align="center">Leverages a lesser known technique to debug Windows Applications. </h4>

![screenshot](https://raw.githubusercontent.com/H-Bains/IFEODebugger/master/IFEODebugger.gif)


## Description

Image File Execution Options (IFEO) provide developers the ability to attach a debugger to a Windows application. 
The debugger application is prepended to the target application, launching the target application under the debugger.
The debugger application is added as a ```debugger``` under ```HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\```.
IFEODebugger sets itself as the debugger for the League of Legends client, strips the --no-proxy-server flag, and relaunches the client, allowing network analysis.
  
## Key Features

* Strips --no-proxy-server flag from the LCU
  - Allows for network traffic analysis via a web debugging proxy such as Fiddler

## How To Use

To use this application, make sure you are on a Windows machine with administrator privileges.

## License

MIT

---
