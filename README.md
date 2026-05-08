# modem73interface

modem73interface is a Reticulum interface for the modem73 KISS TNC. It enables any HF/VHF/UHF radio to operate with Reticulum

Drop this file into ~/.reticulum/interfaces/ and add an entry like:
```
[[MODEM73]]
type = Modem73Interface
enabled = yes
target_host = 127.0.0.1
target_port = 8001
control_host = 127.0.0.1
control_port = 8073
```
where the target host, port, and control host and port are pointing to your runnning modem73 instance 
