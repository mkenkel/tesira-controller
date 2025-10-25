#!/usr/bin/env python3
"""
Basic SSH GUI for sending control commands to an audio matrix.

This version includes performance and reliability improvements:
- Paramiko connect now disables agent/key lookups (look_for_keys=False, allow_agent=False)
  to avoid auth delays when using password or empty-password authentication.
- After connect we set TCP_NODELAY on the underlying socket to reduce packet coalescing delays.
- A persistent interactive shell (invoke_shell) is opened and reused for sending commands,
  which is much faster than opening a new exec/channel for each command.
- send_command uses a non-blocking read loop (recv_ready) and returns as soon as no new data
  arrives for a short grace period or when a total timeout is reached. This avoids blocking
  on stdout.read() until EOF.
- Shell usage is serialized with a threading.Lock so concurrent sends won't interleave.
- Exec_command(get_pty=True) is still used as a fallback if the persistent shell is not available.

Keep in mind:
- The device's command terminator (usually '\r' or '\r\n') must be included in the command strings.
- If your device emits a known prompt, we could detect it and return earlier; currently we use
  a short "no-data" window to decide the response is finished.
"""

import json
import os
import threading
import time
import socket
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

import paramiko

COMMANDS_FILE = "commands.json"


class SSHController:
    def __init__(self):
        self.client = None
        self.shell = None
        self.shell_lock = threading.Lock()

    def connect(
        self, host, port=22, username=None, password=None, pkey_path=None, timeout=10
    ):
        """
        Connect to the SSH server. For password auth we disable key/agent lookups to avoid delays.
        On success we open a persistent interactive shell (invoke_shell) for fast repeated commands.
        """
        if self.client:
            self.disconnect()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if pkey_path:
                key = paramiko.RSAKey.from_private_key_file(pkey_path)
                client.connect(
                    hostname=host,
                    port=int(port),
                    username=username,
                    pkey=key,
                    timeout=timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    auth_timeout=10,
                )
            else:
                # pass password (can be empty string) — Paramiko will attempt password auth
                client.connect(
                    hostname=host,
                    port=int(port),
                    username=username,
                    password=password,
                    timeout=timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    auth_timeout=10,
                )

            # Set TCP_NODELAY if possible (reduce small packet latency)
            try:
                transport = client.get_transport()
                if (
                    transport is not None
                    and hasattr(transport, "sock")
                    and transport.sock is not None
                ):
                    transport.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                # Non-fatal; continue
                pass

            # Open a persistent interactive shell for fast repeated commands.
            try:
                shell = client.invoke_shell()
                # small non-blocking timeout for recv calls (we manage timing ourselves)
                shell.settimeout(0.1)
                self.shell = shell
            except Exception:
                self.shell = None

            self.client = client
            return True, "Connected"
        except Exception as e:
            # ensure we clean up partially created state
            try:
                client.close()
            except Exception:
                pass
            self.client = None
            self.shell = None
            return False, f"Connection failed: {e}"

    def disconnect(self):
        # Close shell first
        try:
            if self.shell:
                try:
                    self.shell.close()
                except Exception:
                    pass
                self.shell = None
        except Exception:
            pass
        # Then close client
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass
        self.client = None

    def is_connected(self):
        return self.client is not None

    def _read_from_channel(self, chan, timeout, idle_grace=0.15):
        """
        Read available bytes from a Paramiko channel (chan must support recv_ready/recv).
        Return the aggregated bytes decoded to string.
        idle_grace: seconds to wait after last received chunk before considering output finished.
        """
        end_time = time.time() + timeout
        last_recv = 0
        buf = []
        while time.time() < end_time:
            try:
                if chan.recv_ready():
                    data = chan.recv(4096)
                    if not data:
                        break
                    buf.append(data)
                    last_recv = time.time()
                    continue
            except Exception:
                # recv may raise on timeout/non-blocking; ignore and continue
                pass
            # if we've received something recently, give a short grace window for more data
            if last_recv and (time.time() - last_recv) < idle_grace:
                time.sleep(0.02)
                continue
            # no new data recently; small sleep then check again until total timeout
            time.sleep(0.02)
        try:
            return b"".join(buf).decode(errors="ignore")
        except Exception:
            return ""

    def send_command(self, command, timeout=3):
        """
        Send a command and return (stdout, stderr). Uses the persistent shell if available (fast).
        Otherwise falls back to exec_command(get_pty=True) and reads via non-blocking loop.
        The command will be newline-terminated if not already.
        """
        if not self.client:
            raise RuntimeError("Not connected")

        # Ensure the command ends with newline so remote CLI executes it
        if not command.endswith("\n"):
            command = command + "\n"

        # Prefer the persistent shell (faster for repeated commands)
        if self.shell:
            with self.shell_lock:
                try:
                    # clear any previous buffered data quickly before sending
                    try:
                        # drain any existing data
                        while self.shell.recv_ready():
                            self.shell.recv(4096)
                    except Exception:
                        pass

                    self.shell.send(command)
                    # Read until no new data arrives for a short grace period or total timeout
                    out = self._read_from_channel(
                        self.shell, timeout=timeout, idle_grace=0.15
                    )
                    return out, ""
                except Exception as e:
                    # If shell fails, fall back to exec_command
                    pass

        # Fallback: exec_command with a pty and non-blocking read loop
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=timeout, get_pty=True
            )
            chan = stdout.channel

            # Non-blocking read of stdout / stderr until no more arrives
            out = ""
            err = ""
            # read stdout
            out = self._read_from_channel(chan, timeout=timeout, idle_grace=0.15)
            # read stderr if available via recv_stderr
            try:
                if chan.recv_stderr_ready():
                    # create a small temporary channel-like object for stderr if available
                    stderr_buf = []
                    end_time = time.time() + timeout
                    while time.time() < end_time:
                        if chan.recv_stderr_ready():
                            stderr_buf.append(chan.recv_stderr(4096))
                        else:
                            time.sleep(0.02)
                    try:
                        err = b"".join(stderr_buf).decode(errors="ignore")
                    except Exception:
                        err = ""
            except Exception:
                err = ""

            return out, err
        except Exception as e:
            # Try an invoke_shell quick attempt if exec_command also failed
            try:
                chan = self.client.invoke_shell()
                try:
                    if not command.endswith("\n"):
                        command += "\n"
                    chan.settimeout(0.1)
                    chan.send(command)
                    out = self._read_from_channel(
                        chan, timeout=timeout, idle_grace=0.15
                    )
                    try:
                        chan.close()
                    except Exception:
                        pass
                    return out, ""
                except Exception as e2:
                    try:
                        chan.close()
                    except Exception:
                        pass
                    raise RuntimeError(f"Failed to send command: {e2}")
            except Exception as e2:
                raise RuntimeError(f"Failed to send command: {e} / {e2}")


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Matrix SSH Controller — Basic (patched)")
        self.ssh = SSHController()
        self.commands = {}
        self.load_commands()

        # Connection frame
        conn_frame = tk.Frame(root, padx=6, pady=6)
        conn_frame.grid(row=0, column=0, sticky="ew")

        tk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky="w")
        self.host_entry = tk.Entry(conn_frame, width=20)
        self.host_entry.grid(row=0, column=1, sticky="w")
        tk.Label(conn_frame, text="Port:").grid(
            row=0, column=2, sticky="w", padx=(8, 0)
        )
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "22")
        self.port_entry.grid(row=0, column=3, sticky="w")

        tk.Label(conn_frame, text="User:").grid(
            row=0, column=4, sticky="w", padx=(8, 0)
        )
        self.user_entry = tk.Entry(conn_frame, width=12)
        self.user_entry.grid(row=0, column=5, sticky="w")

        tk.Label(conn_frame, text="Password / Key:").grid(
            row=0, column=6, sticky="w", padx=(8, 0)
        )
        self.pw_entry = tk.Entry(conn_frame, width=16, show="*")
        self.pw_entry.grid(row=0, column=7, sticky="w")

        tk.Button(conn_frame, text="Connect", command=self.on_connect).grid(
            row=0, column=8, padx=(8, 0)
        )
        tk.Button(conn_frame, text="Disconnect", command=self.on_disconnect).grid(
            row=0, column=9, padx=(4, 0)
        )

        # Commands frame
        cmd_frame = tk.Frame(root, padx=6, pady=6)
        cmd_frame.grid(row=1, column=0, sticky="ew")
        tk.Label(cmd_frame, text="Named commands:").grid(row=0, column=0, sticky="w")
        self.command_var = tk.StringVar()
        self.command_menu = tk.OptionMenu(
            cmd_frame, self.command_var, *self.commands.keys()
        )
        self.command_menu.config(width=30)
        self.command_menu.grid(row=0, column=1, sticky="w")
        tk.Button(cmd_frame, text="Send", command=self.on_send_named).grid(
            row=0, column=2, padx=(6, 0)
        )
        tk.Button(cmd_frame, text="Edit Commands", command=self.on_edit_commands).grid(
            row=0, column=3, padx=(6, 0)
        )

        tk.Label(cmd_frame, text="Raw command:").grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )
        self.raw_entry = tk.Entry(cmd_frame, width=90)
        self.raw_entry.grid(row=1, column=1, columnspan=3, sticky="w", pady=(6, 0))
        tk.Button(cmd_frame, text="Send Raw", command=self.on_send_raw).grid(
            row=1, column=4, padx=(6, 0)
        )

        # Response / log area
        log_frame = tk.Frame(root, padx=6, pady=6)
        log_frame.grid(row=2, column=0, sticky="nsew")
        root.grid_rowconfigure(2, weight=1)
        root.grid_columnconfigure(0, weight=1)

        tk.Label(log_frame, text="Response / Log:").pack(anchor="w")
        self.log = ScrolledText(log_frame, height=20, state="normal")
        self.log.pack(fill="both", expand=True)

        # Menu
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(
            label="Load commands...", command=self.on_load_commands_file
        )
        filemenu.add_command(
            label="Save commands as...", command=self.on_save_commands_file
        )
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # Status
        self.append_log(
            "Ready. Load or edit commands and connect to your device. (Patched for speed.)"
        )

        # Select default if any
        if self.commands:
            first = next(iter(self.commands.keys()))
            self.command_var.set(first)
            self.update_command_menu()

    def append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def load_commands(self, path=COMMANDS_FILE):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.commands = json.load(f)
            except Exception:
                self.commands = {}
        else:
            # create a starter file with placeholders
            self.commands = {
                "Example: RAW echo": "SAMPLE_COMMAND_PLACEHOLDER\\r\\n",
                "Example: MuteAll": "MUTE ALL PLACEHOLDER\\r\\n",
            }
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.commands, f, indent=2)
            except Exception:
                pass

    def save_commands(self, path=COMMANDS_FILE):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.commands, f, indent=2)
            self.append_log(f"Commands saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save commands: {e}")

    def update_command_menu(self):
        menu = self.command_menu["menu"]
        menu.delete(0, "end")
        for key in self.commands.keys():
            menu.add_command(label=key, command=lambda k=key: self.command_var.set(k))

    def on_connect(self):
        host = self.host_entry.get().strip()
        if not host:
            messagebox.showerror("Missing", "Host required")
            return
        port = self.port_entry.get().strip() or "22"
        user = self.user_entry.get().strip() or None

        # Keep raw password as-is (so we can attempt an actual empty string "")
        pw_raw = self.pw_entry.get()
        if pw_raw is None:
            pw = None
        else:
            pw = pw_raw  # can be empty string ""

        pkey = None
        # Ask user if they want to use a key file (optional)
        if messagebox.askyesno(
            "Authentication", "Use a private key file instead of password?"
        ):
            pkey = filedialog.askopenfilename(title="Select private key file")
            if not pkey:
                pkey = None

        self.append_log(f"Connecting to {host}:{port} as {user or 'anonymous'} ...")

        def connect_thread():
            ok, msg = self.ssh.connect(host, port, user, pw, pkey)
            self.append_log(msg)
            if ok:
                # Report whether we have a persistent shell
                if self.ssh.shell:
                    self.append_log(
                        "Connection established. Persistent shell opened (fast commands)."
                    )
                else:
                    self.append_log(
                        "Connection established. Persistent shell not available; using exec_command fallback."
                    )
            else:
                self.append_log("Connection failed.")

        threading.Thread(target=connect_thread, daemon=True).start()

    def on_disconnect(self):
        self.ssh.disconnect()
        self.append_log("Disconnected.")

    def send_command_and_log(self, command):
        if not self.ssh.is_connected():
            messagebox.showerror("Not connected", "Connect first")
            return
        # Show the raw (escaped) form so user can see control chars
        display_cmd = command.replace("\r", "\\r").replace("\n", "\\n")
        self.append_log(f">>> {display_cmd}")

        def send_thread():
            try:
                out, err = self.ssh.send_command(command)
                if out:
                    # Show cleaned output; preserve newlines
                    self.append_log("OUT: " + out.strip())
                if err:
                    self.append_log("ERR: " + err.strip())
                if not out and not err:
                    self.append_log("(no response)")
            except Exception as e:
                self.append_log(f"Send failed: {e}")

        threading.Thread(target=send_thread, daemon=True).start()

    def on_send_named(self):
        key = self.command_var.get()
        if not key:
            messagebox.showerror("No command", "Select a named command")
            return
        cmd = self.commands.get(key, "")
        # Allow users to include escaped sequences like \\r or \\n in JSON; expand them
        try:
            real_cmd = cmd.encode("utf-8").decode("unicode_escape")
        except Exception:
            real_cmd = cmd
        self.send_command_and_log(real_cmd)

    def on_send_raw(self):
        cmd = self.raw_entry.get()
        if not cmd:
            messagebox.showerror("No command", "Enter raw command to send")
            return
        # Interpret escaped sequences in the raw entry if present
        try:
            real_cmd = cmd.encode("utf-8").decode("unicode_escape")
        except Exception:
            real_cmd = cmd
        self.send_command_and_log(real_cmd)

    def on_edit_commands(self):
        editor = CommandsEditor(self.root, self.commands)
        self.root.wait_window(editor.top)
        if editor.updated:
            self.commands = editor.commands
            self.save_commands(COMMANDS_FILE)
            self.update_command_menu()

    def on_load_commands_file(self):
        path = filedialog.askopenfilename(
            title="Load commands JSON",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                commands = json.load(f)
            self.commands = commands
            self.save_commands(COMMANDS_FILE)
            self.update_command_menu()
            self.append_log(f"Loaded commands from {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load commands: {e}")

    def on_save_commands_file(self):
        path = filedialog.asksaveasfilename(
            title="Save commands as",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.commands, f, indent=2)
            self.append_log(f"Saved commands to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save commands: {e}")


class CommandsEditor:
    def __init__(self, parent, commands):
        self.top = tk.Toplevel(parent)
        self.top.title("Edit Commands")
        self.commands = dict(commands)
        self.updated = False

        self.listbox = tk.Listbox(self.top, width=50, height=12)
        self.listbox.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        right = tk.Frame(self.top)
        right.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        tk.Label(right, text="Name:").pack(anchor="w")
        self.name_entry = tk.Entry(right, width=40)
        self.name_entry.pack(anchor="w", pady=(0, 6))

        tk.Label(right, text="Command string (use \\r, \\n if needed):").pack(
            anchor="w"
        )
        self.cmd_entry = tk.Entry(right, width=60)
        self.cmd_entry.pack(anchor="w", pady=(0, 6))

        btn_frame = tk.Frame(right)
        btn_frame.pack(anchor="w", pady=(6, 0))
        tk.Button(btn_frame, text="Add / Update", command=self.on_add_update).grid(
            row=0, column=0, padx=4
        )
        tk.Button(btn_frame, text="Delete", command=self.on_delete).grid(
            row=0, column=1, padx=4
        )
        tk.Button(btn_frame, text="Close", command=self.on_close).grid(
            row=0, column=2, padx=4
        )

        self.refresh_list()

    def refresh_list(self):
        self.listbox.delete(0, "end")
        for k in sorted(self.commands.keys()):
            self.listbox.insert("end", k)

    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        key = self.listbox.get(sel[0])
        self.name_entry.delete(0, "end")
        self.name_entry.insert(0, key)
        self.cmd_entry.delete(0, "end")
        self.cmd_entry.insert(0, self.commands.get(key, ""))

    def on_add_update(self):
        name = self.name_entry.get().strip()
        cmd = self.cmd_entry.get()
        if not name:
            messagebox.showerror("Name required", "Enter a name for the command")
            return
        self.commands[name] = cmd
        self.refresh_list()
        self.updated = True

    def on_delete(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showerror("Select", "Select an entry to delete")
            return
        key = self.listbox.get(sel[0])
        if messagebox.askyesno("Delete", f"Delete command '{key}'?"):
            del self.commands[key]
            self.refresh_list()
            self.updated = True

    def on_close(self):
        self.top.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
