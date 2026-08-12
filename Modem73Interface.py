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
#     # short_frames = auto      # Leave this on auto for best performance
#     # short_mtu = 170

import base64
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
    DEFAULT_BITRATE       = 400
    DEFAULT_SHORT_MTU     = 170
    FRAG_HEADER_SIZE      = 5

    CONTROL_RECONNECT_WAIT = 5
    CONTROL_CONNECT_TIMEOUT = 5

    MODEM_OFDM   = 0
    MODEM_MFSK   = 1
    MODEM_ROBUST = 2

    OFDM_MODULATIONS = ["BPSK", "QPSK", "8PSK", "QAM16",
                        "QAM64", "QAM256", "QAM1024", "QAM4096"]
    OFDM_CODE_RATES  = ["1/2", "2/3", "3/4", "5/6", "1/4", "1/2x2", "1/4x2"]

    ROBUST_SHORT_OFFSET = 5
    ROBUST_MODE_MAX     = 12
    ROBUST_SHORT_MODE   = {0: 5, 1: 6, 2: 7, 3: 8, 4: 9, 10: 11}
    ROBUST_BPS = [1150, 585, 296, 296, 149, 732, 378, 194, 197, 99,
                  782, 513, 474]
    # Timeout-oriented effective bitrates (legacy static table, csma_overhead = no)
    ROBUST_TIMEOUT_BPS = [295, 100, 75, 75, 38, 185, 95, 50, 50, 25,
                          196, 128, 118]
    MFSK_TIMEOUT_BPS   = 10

    # Frame airtimes in seconds, for CSMA-aware effective bitrate
    ROBUST_AIRTIME = [3.56, 7.00, 13.80, 13.80, 27.48,
                      1.88, 3.64, 7.08, 7.00, 13.88,
                      5.24, 2.68, 0.54]
    # (short, normal, long) airtime per OFDM modulation family
    OFDM_AIRTIME = {
        "BPSK":    (1.64, 2.73, 4.92),
        "QPSK":    (1.09, 2.73, 4.92),
        "8PSK":    (2.05, 3.55, 6.56),
        "QAM16":   (1.09, 2.73, 4.92),
        "QAM64":   (2.05, 3.55, 6.56),
        "QAM256":  (1.64, 2.73, 4.92),
        "QAM1024": (2.32, 4.10, 4.10),
        "QAM4096": (2.05, 3.55, 3.55),
    }
    CSMA_KEYUP_S = 0.65
    CSMA_BURST_GAP_S = 0.2
    RANKED_SLOT_S = 1.5
    RANKED_YIELD_BUCKETS = 4
    RANKED_QUIET_S = 1.0
    LEAD_TONE_S = 0.8
    CSMA_THRESHOLD = 0
    CSMA_SYNC = 1
    CSMA_RANKED = 2
    DEFAULT_TIMEOUT_MARGIN = 0.35
    MIN_CHANNEL_SHARE = 0.25

    PKT_LINKREQUEST = 0x02
    PKT_PROOF       = 0x03
    CTX_LRRTT       = 0xFE
    CTX_LRPROOF     = 0xFF

    def __init__(self, owner, configuration):
        c = Interface.get_config_obj(configuration)

        target_host  = c["target_host"]  if "target_host"  in c else "127.0.0.1"
        target_port  = int(c["target_port"]) if "target_port" in c else self.DEFAULT_KISS_PORT
        control_host = c["control_host"] if "control_host" in c else target_host
        control_port = int(c["control_port"]) if "control_port" in c else self.DEFAULT_CONTROL_PORT
        mtu_overhead = int(c["mtu_overhead"]) if "mtu_overhead" in c else self.DEFAULT_MTU_OVERHEAD
        bitrate      = int(c["bitrate"]) if "bitrate" in c else self.DEFAULT_BITRATE
        auto_frag    = c.as_bool("auto_fragmentation") if "auto_fragmentation" in c else True
        short_frames = str(c["short_frames"]).lower() if "short_frames" in c else "auto"
        short_mtu    = int(c["short_mtu"]) if "short_mtu" in c else self.DEFAULT_SHORT_MTU
        handshake_x2 = c.as_bool("handshake_x2") if "handshake_x2" in c else False
        proof_x2     = c.as_bool("proof_x2") if "proof_x2" in c else False
        auto_bitrate = c.as_bool("auto_bitrate") if "auto_bitrate" in c else True
        csma_overhead = c.as_bool("csma_overhead") if "csma_overhead" in c else True
        csma          = c.as_bool("csma") if "csma" in c else True
        timeout_margin = float(c["timeout_margin"]) if "timeout_margin" in c else self.DEFAULT_TIMEOUT_MARGIN

        if short_frames not in ("off", "auto", "always"):
            RNS.log(
                f"Modem73Interface: invalid short_frames value \"{short_frames}\", using \"off\"",
                RNS.LOG_WARNING,
            )
            short_frames = "off"

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

        self._short_policy      = short_frames
        self._short_mtu         = short_mtu
        self._short_mtu_cfg     = short_mtu
        self._short_oper_mode   = None
        self._short_tx_count    = 0
        self._always_applied    = False
        self._handshake_x2      = handshake_x2
        self._proof_x2          = proof_x2
        self._auto_bitrate      = auto_bitrate
        self._csma_overhead     = csma_overhead
        self._timeout_margin    = max(0.05, min(1.0, timeout_margin))
        self._last_cfg          = None
        self._initial_cfg       = None
        self._population        = 0
        self._occupancy_pct     = 0
        self._status_interval   = 30
        self._last_status_req   = 0

        self._csma_default      = csma
        self.csma_enabled       = csma
        self.csma_population    = 0

        self.r_stat_rssi = None
        self.r_stat_snr  = None
        self.r_stat_q    = None


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
        self._apply_path_request_window()
        if self._initial_cfg is not None:
            self._sync_from_config(self._initial_cfg)

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
                self._initial_cfg = resp
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
                s.settimeout(self._status_interval)
                self._control_socket = s
                RNS.log(
                    f"Modem73Interface[{self.name}]: control port connected "
                    f"({self.control_host}:{self.control_port})",
                    RNS.LOG_VERBOSE,
                )






                self._send_cmd(s, {"cmd": "get_config"})






                self._send_cmd(s, {"cmd": "get_status"})
                self._last_status_req = time.time()

                while not self._control_stop and not self.detached:
                    try:
                        msg = self._recv_msg(s)
                    except socket.timeout:
                        msg = False
                    if msg is None:
                        break
                    if msg is not False:
                        self._handle_control_msg(msg)
                    now = time.time()
                    if now - self._last_status_req >= self._status_interval:
                        self._last_status_req = now
                        with self._control_lock:
                            self._send_cmd(s, {"cmd": "get_status"})

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
            self._always_applied = False

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

        # rx_frame event: { "event": "rx_frame", "snr":, "ber_pct":, "level_db": }
        if msg.get("event") == "rx_frame":
            self._update_rx_stats(msg)
            return

        if "population" in msg or "occupancy_pct" in msg:
            self._update_channel_load(msg)
            return

        # get_config reply: config fields at top level, with "ok": true
        if "payload_size" in msg:
            self._sync_from_config(msg)

    def _update_channel_load(self, msg):
        try:
            changed = False
            occ = msg.get("occupancy_pct")
            if occ is not None:
                occ = max(0, min(100, int(occ)))
                if occ // 10 != self._occupancy_pct // 10:
                    changed = True
                self._occupancy_pct = occ
            pop = msg.get("population")
            if pop is not None:
                pop = int(pop)
                if pop >= 0 and pop != self._population:
                    self._population = pop
                    self.csma_population = pop
                    RNS.log(
                        f"Modem73Interface[{self.name}]: channel population {pop} "
                        f"other station(s), occupancy {self._occupancy_pct}%",
                        RNS.LOG_INFO,
                    )
                    changed = True
            if changed and self._last_cfg is not None:
                self._maybe_update_bitrate(self._last_cfg)
        except Exception as e:
            RNS.log(
                f"Modem73Interface[{self.name}]: could not update channel load: {e}",
                RNS.LOG_WARNING,
            )

    def _update_rx_stats(self, msg):
        try:
            level = msg.get("level_db")
            snr = msg.get("snr")
            ber_pct = msg.get("ber_pct")

            if level is not None:
                self.r_stat_rssi = round(float(level), 1)
            if snr is not None:
                self.r_stat_snr = round(float(snr), 1)
            if ber_pct is not None and float(ber_pct) >= 0:
                self.r_stat_q = max(0, min(100, round(100.0 - float(ber_pct))))
            else:
                self.r_stat_q = None
        except Exception as e:
            RNS.log(
                f"Modem73Interface[{self.name}]: could not update rx stats: {e}",
                RNS.LOG_WARNING,
            )

    def _sync_from_config(self, cfg):
        self._last_cfg = cfg
        self.csma_enabled = bool(cfg.get("csma_enabled", self._csma_default))
        mode = self._csma_mode(cfg)
        if mode != getattr(self, "_csma_mode_seen", None):
            self._csma_mode_seen = mode
            names = {self.CSMA_THRESHOLD: "THRESHOLD", self.CSMA_SYNC: "SYNC",
                     self.CSMA_RANKED: "RANKED"}
            legacy = "" if cfg.get("csma_sync_only") is not None else " pre 2.3.0"
            RNS.log(
                f"Modem73Interface[{self.name}]: CSMA mode {names[mode]}{legacy}",
                RNS.LOG_INFO,
            )

        if "payload_size" in cfg:
            self._apply_payload_size(cfg["payload_size"])

        self._maybe_update_bitrate(cfg)
        self._update_short_mode(cfg)

        if self._short_policy == "always" and not self._always_applied:
            self._apply_always_short(cfg)

    ### EFFECTIVE BITRATE

    def _phy_profile(self, cfg):
        mt = cfg.get("modem_type")
        if mt == self.MODEM_ROBUST:
            rm = cfg.get("robust_mode")
            if rm is None or not (0 <= rm <= self.ROBUST_MODE_MAX):
                return None
            return (self.ROBUST_BPS[rm], self.ROBUST_AIRTIME[rm])
        if mt == self.MODEM_OFDM:
            airs = self.OFDM_AIRTIME.get(cfg.get("modulation"))
            fs = cfg.get("frame_size")
            payload = cfg.get("payload_size")
            if airs is None or fs is None or not payload:
                return None
            air = airs[max(0, min(2, int(fs)))]
            return (int(payload) * 8 / air, air)
        return None

    def _csma_mode(self, cfg):
        sync = cfg.get("csma_sync_only")
        if sync is None:
            return self.CSMA_THRESHOLD
        if not sync:
            return self.CSMA_THRESHOLD
        return self.CSMA_RANKED if cfg.get("csma_ranked") else self.CSMA_SYNC

    def _dcd_detect_s(self, cfg):
        if cfg.get("csma_fast_floor"):
            return 0.55
        return 0.78 if cfg.get("modem_type") == self.MODEM_ROBUST else 1.31

    def _csma_per_frame_overhead(self, cfg, airtime):
        if not cfg.get("csma_enabled", self._csma_default):
            return 0.0
        mode = self._csma_mode(cfg)
        stations = max(1, self._population + 1)
        slot_ms = max(1, int(cfg.get("slot_time_ms") or 500))

        if mode == self.CSMA_RANKED:
            worst_rank = (stations - 1) + (self.RANKED_YIELD_BUCKETS - 1)
            return (self.RANKED_QUIET_S + worst_rank * self.RANKED_SLOT_S
                    + self.LEAD_TONE_S)

        quiet_ms = cfg.get("csma_quiet_ms") or 0
        if quiet_ms <= 0:
            quiet_ms = min(max(airtime * 250.0, 300.0), 3500.0)
        cw = max(2, int(cfg.get("csma_cw") or 8))
        if mode == self.CSMA_SYNC:
            det = self._dcd_detect_s(cfg)
            slots = min(16, max(6, 3 * stations))
            window = max(slots * (det + 0.15),
                         cw * slot_ms / 500.0,
                         4 * slot_ms / 1000.0)
        else:
            window = cw * slot_ms / 1000.0
        return quiet_ms / 1000.0 + window + self.CSMA_KEYUP_S

    def _timeout_bitrate(self, cfg):
        mt = cfg.get("modem_type")
        if mt == self.MODEM_MFSK:
            return self.MFSK_TIMEOUT_BPS
        if not self._csma_overhead:
            if mt == self.MODEM_ROBUST:
                rm = cfg.get("robust_mode")
                if rm is not None and 0 <= rm <= self.ROBUST_MODE_MAX:
                    return self.ROBUST_TIMEOUT_BPS[rm]
            return None
        prof = self._phy_profile(cfg)
        if prof is None:
            return None
        phy, air = prof
        overhead = self._csma_per_frame_overhead(cfg, air)
        duty = air / (air + overhead) if overhead > 0 else 1.0
        share = 1.0
        if cfg.get("csma_enabled", self._csma_default):
            share = max(1.0 - self._occupancy_pct / 100.0, self.MIN_CHANNEL_SHARE)
        return max(8, int(phy * duty * share))

    def _maybe_update_bitrate(self, cfg):
        if not self._auto_bitrate:
            return
        new_bitrate = self._timeout_bitrate(cfg)
        if new_bitrate is not None and new_bitrate != self.bitrate:
            RNS.log(
                f"Modem73Interface[{self.name}]: bitrate {self.bitrate} -> "
                f"{new_bitrate}"
                + (" (CSMA-aware)" if self._csma_overhead else ""),
                RNS.LOG_INFO,
            )
            self.bitrate = new_bitrate
            self._apply_path_request_window()

    def _apply_path_request_window(self):
        if not self.bitrate:
            return
        needed = int(3 * (RNS.Reticulum.MTU * 8 / self.bitrate)) + 10
        current = RNS.Transport.PATH_REQUEST_TIMEOUT
        if needed > current:
            RNS.Transport.PATH_REQUEST_TIMEOUT = needed
            RNS.log(
                f"Modem73Interface[{self.name if hasattr(self, 'name') else 'm73'}]: "
                f"path request window {current}s -> {needed}s for {self.bitrate} bps channel",
                RNS.LOG_INFO,
            )

    ### SHORT FRAME HANDLING

    def _update_short_mode(self, cfg):
        modem_type = cfg.get("modem_type")
        override = None

        if modem_type == self.MODEM_ROBUST:
            rm = cfg.get("robust_mode")
            short_rm = self.ROBUST_SHORT_MODE.get(rm)
            if short_rm is not None:
                override = short_rm
                self._short_mtu = min(
                    self._short_mtu_cfg,
                    self.DEFAULT_SHORT_MTU - self.FRAG_HEADER_SIZE,
                )
            else:
                self._short_mtu = self._short_mtu_cfg

        elif modem_type == self.MODEM_OFDM:
            if not cfg.get("short_frame", False):
                try:
                    mod  = self.OFDM_MODULATIONS.index(cfg.get("modulation"))
                    rate = self.OFDM_CODE_RATES.index(cfg.get("code_rate"))
                    override = (mod << 4) | (rate << 1)
                except (ValueError, TypeError):
                    override = None

        if override != self._short_oper_mode:
            self._short_oper_mode = override
            if self._short_policy == "auto":
                if override is not None:
                    RNS.log(
                        f"Modem73Interface[{self.name}]: short-frame bypass active "
                        f"(mode override {override}, threshold {self._short_mtu} bytes)",
                        RNS.LOG_INFO,
                    )
                else:
                    RNS.log(
                        f"Modem73Interface[{self.name}]: short-frame bypass inactive "
                        f"for current TNC mode",
                        RNS.LOG_INFO,
                    )

    def _apply_always_short(self, cfg):
        modem_type = cfg.get("modem_type")
        msg = None

        if modem_type == self.MODEM_ROBUST:
            rm = cfg.get("robust_mode")
            short_rm = self.ROBUST_SHORT_MODE.get(rm)
            if short_rm is not None:
                msg = {"cmd": "set_config", "robust_mode": short_rm}
        elif modem_type == self.MODEM_OFDM:
            if not cfg.get("short_frame", False):
                msg = {"cmd": "set_config", "short_frame": True}

        if msg is None:
            self._always_applied = True
            return

        with self._control_lock:
            sock = self._control_socket
            if sock is None:
                return
            try:
                self._send_cmd(sock, msg)
                self._always_applied = True
                RNS.log(
                    f"Modem73Interface[{self.name}]: switched modem73 to short-frames "
                    f"mode ({msg})",
                    RNS.LOG_INFO,
                )
            except Exception as e:
                RNS.log(
                    f"Modem73Interface[{self.name}]: failed to apply "
                    f"short_frames=always: {e}",
                    RNS.LOG_WARNING,
                )

    def _is_handshake(self, data):
        if len(data) < 19:
            return False
        flags = data[0]
        if (flags & 0x03) == self.PKT_LINKREQUEST:
            return True
        ctx_offset = 34 if (flags >> 6) & 0x01 else 18
        if len(data) <= ctx_offset:
            return False
        return data[ctx_offset] in (self.CTX_LRRTT, self.CTX_LRPROOF)

    def _is_proof(self, data):
        if len(data) < 19:
            return False
        return (data[0] & 0x03) == self.PKT_PROOF

    def process_outgoing(self, data):
        copies = 1
        if getattr(self, "ifac_identity", None) is None:
            if self._handshake_x2 and self._is_handshake(data):
                copies = 2
            elif self._proof_x2 and self._is_proof(data):
                copies = 2

        for _ in range(copies):
            if (self._short_policy == "auto"
                    and self.online
                    and self._short_oper_mode is not None
                    and len(data) <= self._short_mtu
                    and self._send_short_frame(data)):
                continue
            super().process_outgoing(data)

    def _send_short_frame(self, data):
        msg = {
            "cmd": "tx",
            "data": base64.b64encode(bytes(data)).decode("ascii"),
            "oper_mode": int(self._short_oper_mode),
        }
        with self._control_lock:
            sock = self._control_socket
            if sock is None:
                return False
            try:
                self._send_cmd(sock, msg)
            except Exception as e:
                RNS.log(
                    f"Modem73Interface[{self.name}]: short-frame tx failed, "
                    f"falling back to KISS: {e}",
                    RNS.LOG_WARNING,
                )
                return False

        self.txb += len(data)
        self._short_tx_count += 1
        return True






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
