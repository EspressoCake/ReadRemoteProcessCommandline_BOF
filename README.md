# Read Remote Process Commandline BOF
`BOF` to read the startup arguments of a remote process, when provided a process ID (PID)

#### Why:
A few use-cases that immediately come to mind:
  1: Secondary selection for process injection
  2: Inspection of remote commandline arguments to identify possible configuration paths for applications 

#### Building
```bash
cd src
make
```

#### Usage
- Load the `remote_process_commandline.cna` file from the `dist` folder.
- Within a `beacon`: `remote_process_commandline process_id_number`

#### Images
![Usage](https://i.ibb.co/0ns6ZkT/remote-cli.png)

