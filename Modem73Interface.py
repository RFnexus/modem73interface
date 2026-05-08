# Modem73Interface.py
#
# A Reticulum CustomInterface for MODEM73.
#
# Drop this file into ~/.reticulum/interfaces/ and add an entry like:
#
#   [[MODEM73]]
#     type = Modem73Interface
#     enabled = yes
#     target_host = 127.0.0.1
#     target_port = 8001
#     control_host = 127.0.0.1
#     control_port = 8073
#     # Optional, defaults shown:
#     # mtu_overhead = 15
#     # bitrate = 600

import json
import socket
import struct
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface
from RNS.Interfaces.TCPInterface import TCPClientInterface


class Modem73Interface(TCPClientInterface):
    DEFAULT_IFAC_SIZE = 8

    DEFAULT_KISS_PORT     = 8001
    DEFAULT_CONTROL_PORT  = 8073
    DEFAULT_MTU_OVERHEAD  = 15
    DEFAULT_BITRATE       = 600

    CONTROL_RECONNECT_WAIT = 5
    CONTROL_CONNECT_TIMEOUT = 5

    def __init__(self, owner, configuration):
        c = Interface.get_config_obj(configuration)

        target_host  = c["target_host"]  if "target_host"  in c else "127.0.0.1"
        target_port  = int(c["target_port"]) if "target_port" in c else self.DEFAULT_KISS_PORT
        control_host = c["control_host"] if "control_host" in c else target_host
        control_port = int(c["control_port"]) if "control_port" in c else self.DEFAULT_CONTROL_PORT
        mtu_overhead = int(c["mtu_overhead"]) if "mtu_overhead" in c else self.DEFAULT_MTU_OVERHEAD
        bitrate      = int(c["bitrate"]) if "bitrate" in c else self.DEFAULT_BITRATE
        auto_frag    = c.as_bool("auto_fragmentation") if "auto_fragmentation" in c else True

        self.control_host    = control_host
        self.control_port    = control_port
        self.mtu_overhead    = mtu_overhead
        self._fixed_bitrate  = bitrate
        self._auto_frag      = auto_frag
        self._frag_target    = None  # last fragmentation state we asserted
        self._control_socket = None
        self._control_lock   = threading.Lock()
        self._control_thread = None
        self._control_stop   = False


        initial_mtu = self._query_initial_mtu()
        if initial_mtu is None:
            initial_mtu = max(RNS.Reticulum.MTU, 500)
            RNS.log(
                f"Modem73Interface: could not reach control port at "
                f"{control_host}:{control_port}, starting with MTU {initial_mtu}",
                RNS.LOG_WARNING,
            )



        c["kiss_framing"] = "true"
        c["target_host"]  = target_host
        c["target_port"]  = str(target_port)
        c["fixed_mtu"]    = str(initial_mtu)

        super().__init__(owner, c)

        # pin our advertisted bitrate
        self.bitrate = self._fixed_bitrate 

        # track config changes
        self._control_thread = threading.Thread(target=self._control_loop, daemon=True)
        self._control_thread.start()

    ### MTU HELPERS

    def _compute_mtu(self, payload_size):
        raw = int(payload_size) - self.mtu_overhead
        return max(raw, RNS.Reticulum.MTU)

    def _needs_fragmentation(self, payload_size):
        return (int(payload_size) - self.mtu_overhead) < RNS.Reticulum.MTU

    def _apply_payload_size(self, payload_size):
        new_mtu = self._compute_mtu(payload_size)
        if new_mtu != getattr(self, "HW_MTU", None):
            old = getattr(self, "HW_MTU", None)
            self.HW_MTU = new_mtu
            RNS.log(
                f"Modem73Interface[{self.name}]: payload_size={payload_size}, "
                f"HW_MTU {old} -> {new_mtu}",
                RNS.LOG_INFO,
            )

        if self._auto_frag:
            want_frag = self._needs_fragmentation(payload_size)
            if want_frag != self._frag_target:
                if self._set_fragmentation(want_frag):
                    self._frag_target = want_frag
                    RNS.log(
                        f"Modem73Interface[{self.name}]: fragmentation "
                        f"{'enabled' if want_frag else 'disabled'} "
                        f"(payload_size={payload_size}, threshold={RNS.Reticulum.MTU + self.mtu_overhead})",
                        RNS.LOG_INFO,
                    )

    def _set_fragmentation(self, enabled):
        msg = {"cmd": "set_config", "fragmentation_enabled": bool(enabled)}
        with self._control_lock:
            sock = self._control_socket
            if sock is None:
                return False
            try:
                self._send_cmd(sock, msg)
                return True
            except Exception as e:
                RNS.log(
                    f"Modem73Interface[{self.name}]: failed to set "
                    f"fragmentation_enabled={enabled}: {e}",
                    RNS.LOG_WARNING,
                )
                return False


    @staticmethod
    def _send_cmd(sock, obj):
        data = json.dumps(obj).encode("utf-8")
        sock.sendall(struct.pack(">I", len(data)) + data)

    @staticmethod
    def _recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @classmethod
    def _recv_msg(cls, sock):
        hdr = cls._recv_exact(sock, 4)
        if not hdr:
            return None
        (length,) = struct.unpack(">I", hdr)
        if length == 0:
            return {}
        body = cls._recv_exact(sock, length)
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _query_initial_mtu(self):
        try:
            s = socket.create_connection(
                (self.control_host, self.control_port),
                timeout=self.CONTROL_CONNECT_TIMEOUT,
            )
            try:
                self._send_cmd(s, {"cmd": "get_config"})
                resp = self._recv_msg(s)
            finally:
                try: s.close()
                except Exception: pass
            if resp and "payload_size" in resp:
                return self._compute_mtu(resp["payload_size"])
        except Exception as e:
            RNS.log(f"Modem73Interface: initial control-port query failed: {e}", RNS.LOG_WARNING)
        return None

    def _control_loop(self):
        while not self._control_stop and not self.detached:
            try:
                s = socket.create_connection(
                    (self.control_host, self.control_port),
                    timeout=self.CONTROL_CONNECT_TIMEOUT,
                )
                s.settimeout(None)
                self._control_socket = s
                RNS.log(
                    f"Modem73Interface[{self.name}]: control port connected "
                    f"({self.control_host}:{self.control_port})",
                    RNS.LOG_VERBOSE,
                )






                self._send_cmd(s, {"cmd": "get_config"})






                while not self._control_stop and not self.detached:
                    msg = self._recv_msg(s)
                    if msg is None:
                        break
                    self._handle_control_msg(msg)

            except Exception as e:
                if not self._control_stop:
                    RNS.log(
                        f"Modem73Interface[{self.name}]: control port error: {e}",
                        RNS.LOG_WARNING,
                    )

            try:
                if self._control_socket:
                    self._control_socket.close()
            except Exception:
                pass
            self._control_socket = None

            if self._control_stop or self.detached:
                break
            time.sleep(self.CONTROL_RECONNECT_WAIT)

    def _handle_control_msg(self, msg):
        if not isinstance(msg, dict):
            return

        # config_changed event: { "event": "config_changed", "config": {...} }
        if msg.get("event") == "config_changed":
            cfg = msg.get("config")
            if isinstance(cfg, dict):
                self._sync_from_config(cfg)
            return

        # get_config reply: config fields at top level, with "ok": true
        if "payload_size" in msg:
            self._sync_from_config(msg)

    def _sync_from_config(self, cfg):
        if "payload_size" in cfg:
            self._apply_payload_size(cfg["payload_size"])






    def detach(self):
        self._control_stop = True
        try:
            if self._control_socket is not None:
                try:
                    self._control_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._control_socket.close()
        except Exception:
            pass
        self._control_socket = None
        super().detach()

    def __str__(self):
        ip = getattr(self, "target_ip", self.control_host)
        port = getattr(self, "target_port", "?")
        if ip and ":" in str(ip):
            ip_str = f"[{ip}]"
        else:
            ip_str = f"{ip}"
        return f"Modem73Interface[{self.name}/{ip_str}:{port}]"


interface_class = Modem73Interface
