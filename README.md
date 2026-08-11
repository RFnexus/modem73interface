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

## Notes ! IMPORTANT !
When using modes that are slow, like the ROBUST HF modes or anything under 2000 bps, Applications that use LXMF like MeshChat, MeshChatX, Sideband, and Columba need LXMF constants that are not tuned for slower interfaces. They will spam the queue with many path requests and retries on first opportunistic attempt (sending when they aren't in the patht able, or not over a link).

When available, send messages over a direct link versus sending LXMF messages opportunistically. Ensure that all peers known eachother in each's announce table and have a fresh understanding of the topology when using modem73 with Reticulum


# Tips
- All peers using modem73 should have eachother's announces in their  path table. It's best to  Announce each time rnsd or other Reticulum programs are spun up when using modem73 as an Interface. 
- It's best to use modes that don't require fragmentation when conditions allow for it. 
- For Transports that connect modem73 to a faster / noisier medium like TCP/IP (such as the public Reticulum network), they should always be configured to `boundary` mode (See: https://reticulum.network/manual/interfaces.html#interfaces-modes)
- Make sure that CSMA (collision avoidance) is properly configured. Ensure that the level threshold is properly set to avoid collisions
