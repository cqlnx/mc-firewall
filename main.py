import argparse
import ctypes
import ipaddress
import os
import platform
import shutil
import subprocess
import sys
import urllib.request

DEFAULT_URL = "https://data.minescan.xyz/scanners/export?format=ip&includeMinescan=true"
DEFAULT_PORT = 25565
SET_NAME = "minescan_blocklist"
RULE_NAME = "MinescanBlocklist"


def is_admin() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd, input_text=None, check=True):
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def fetch_ip_list(url: str) -> list[str]:
    print(f"[*] Downloading IP list from {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "block-minescan-ips/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")

    ips = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
            ips.append(line)
        except ValueError:
            continue

    if not ips:
        raise RuntimeError("No valid IP addresses found in the downloaded feed.")

    print(f"[*] Parsed {len(ips)} valid IP addresses.")
    return ips


def block_linux_nft(ips: list[str], port: int):
    print("[*] Using nftables backend.")
    table = "inet minescan_filter"

    run(["nft", "add", "table", "inet", "minescan_filter"], check=False)
    run(["nft", "add", "set", "inet", "minescan_filter", SET_NAME,
         "{ type ipv4_addr; flags interval; }"], check=False)
    run(["nft", "flush", "set", "inet", "minescan_filter", SET_NAME])

    elements = ", ".join(ips)
    run(["nft", "add", "element", "inet", "minescan_filter", SET_NAME,
         "{ " + elements + " }"])

    run(["nft", "add", "chain", "inet", "minescan_filter", "input",
     "{ type filter hook input priority 0; policy accept; }"], check=False)

    run(["nft", "flush", "chain", "inet", "minescan_filter", "input"], check=False)

    run(["nft", "add", "rule", "inet", "minescan_filter", "input",
         "tcp", "dport", str(port), "ip", "saddr", f"@{SET_NAME}", "drop"])

    print(f"[+] nftables set '{SET_NAME}' updated with {len(ips)} IPs; "
          f"drop rule active on tcp/{port}.")
    print("    Note: for persistence across reboots, save your ruleset "
          "(e.g. `nft list ruleset > /etc/nftables.conf`) and enable the "
          "nftables service.")


def block_linux_ipset(ips: list[str], port: int):
    print("[*] Using ipset + iptables backend.")
    tmp_set = f"{SET_NAME}_tmp"

    run(["ipset", "create", SET_NAME, "hash:ip", "maxelem", "65536"], check=False)
    run(["ipset", "create", tmp_set, "hash:ip", "maxelem", "65536", "-exist"])
    run(["ipset", "flush", tmp_set])

    for ip in ips:
        run(["ipset", "add", tmp_set, ip, "-exist"])

    run(["ipset", "swap", tmp_set, SET_NAME])
    run(["ipset", "destroy", tmp_set])

    check = run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port),
                 "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"], check=False)
    if check.returncode != 0:
        run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port),
             "-m", "set", "--match-set", SET_NAME, "src", "-j", "DROP"])

    print(f"[+] ipset '{SET_NAME}' updated with {len(ips)} IPs; "
          f"iptables DROP rule active on tcp/{port}.")
    print("    Note: for persistence, use `iptables-save` / the "
          "netfilter-persistent package (Debian/Ubuntu) or equivalent.")


def block_linux_firewalld(ips: list[str], port: int):
    print("[*] Using firewalld backend.")
    run(["firewall-cmd", "--permanent", "--new-ipset=" + SET_NAME,
         "--type=hash:ip"], check=False)
    run(["firewall-cmd", "--permanent", "--ipset=" + SET_NAME, "--add-entries="])

    existing = run(["firewall-cmd", "--permanent", "--ipset=" + SET_NAME, "--get-entries"],
                    check=False).stdout.split()
    if existing:
        run(["firewall-cmd", "--permanent", "--ipset=" + SET_NAME,
             "--remove-entries=" + ",".join(existing)], check=False)

    run(["firewall-cmd", "--permanent", "--ipset=" + SET_NAME,
         "--add-entries=" + ",".join(ips)])

    rule = (f'rule family="ipv4" source ipset="{SET_NAME}" '
            f'port protocol="tcp" port="{port}" drop')
    run(["firewall-cmd", "--permanent", "--add-rich-rule=" + rule], check=False)
    run(["firewall-cmd", "--reload"])

    print(f"[+] firewalld ipset '{SET_NAME}' updated with {len(ips)} IPs; "
          f"drop rule active on tcp/{port}.")


def block_linux_ufw(ips: list[str], port: int):
    print("[*] Using ufw backend (no native large-set support; adding rules directly "
          "via the underlying iptables/ipset instead, since ufw doesn't natively "
          "support bulk address sets).")
    block_linux_ipset(ips, port)
    print("    Note: since this bypasses ufw's own rule files, re-running "
          "`ufw reload` or `ufw enable` will NOT remove it, but managing it "
          "via ufw commands directly isn't supported for large IP sets.")


def block_linux(ips: list[str], port: int):
    if which("nft"):
        block_linux_nft(ips, port)
    elif which("ipset") and which("iptables"):
        block_linux_ipset(ips, port)
    elif which("firewall-cmd"):
        block_linux_firewalld(ips, port)
    elif which("ufw"):
        block_linux_ufw(ips, port)
    else:
        raise RuntimeError(
            "No supported firewall tool found (nft, ipset+iptables, "
            "firewalld, or ufw). Install one of these first."
        )


def block_macos_pf(ips: list[str], port: int):
    print("[*] Using pf (Packet Filter) backend.")

    table_file = "/etc/pf.minescan_blocklist.conf"
    anchor_file = "/etc/pf.anchors/minescan"

    with open(table_file, "w") as f:
        f.write("\n".join(ips) + "\n")

    anchor_rules = (
        f'table <minescan_blocklist> persist file "{table_file}"\n'
        f'block drop in quick proto tcp from <minescan_blocklist> to any port {port}\n'
    )
    with open(anchor_file, "w") as f:
        f.write(anchor_rules)

    pf_conf = "/etc/pf.conf"
    with open(pf_conf, "r") as f:
        contents = f.read()

    anchor_line = 'anchor "minescan"'
    load_line = f'load anchor "minescan" from "{anchor_file}"'

    if anchor_line not in contents:
        with open(pf_conf, "a") as f:
            f.write(f'\n{anchor_line}\n{load_line}\n')
        print(f"[*] Registered anchor in {pf_conf}.")

    run(["pfctl", "-f", pf_conf])
    run(["pfctl", "-e"], check=False)

    print(f"[+] pf table 'minescan_blocklist' updated with {len(ips)} IPs; "
          f"drop rule active on tcp/{port}.")
    print("    Note: macOS's Application Firewall (System Settings) is separate "
          "from pf and only controls inbound app-level access, not IP/port "
          "blocking, so pf is the correct layer here.")


def block_windows(ips: list[str], port: int):
    print("[*] Using Windows Firewall backend (PowerShell).")
    batch_size = 200
    remove_cmd = (
        f'Get-NetFirewallRule -DisplayName "{RULE_NAME}_*" -ErrorAction SilentlyContinue '
        f'| Remove-NetFirewallRule'
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", remove_cmd],
                    capture_output=True, text=True)

    batches = [ips[i:i + batch_size] for i in range(0, len(ips), batch_size)]
    for idx, batch in enumerate(batches, start=1):
        addr_list = ",".join(batch)
        rule_name = f"{RULE_NAME}_{idx}"
        cmd = (
            f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound '
            f'-Action Block -Protocol TCP -LocalPort {port} '
            f'-RemoteAddress {addr_list} -Profile Any'
        )
        result = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create rule {rule_name}:\n{result.stderr}")

    print(f"[+] Created {len(batches)} Windows Firewall rule(s) covering "
          f"{len(ips)} IPs; inbound TCP/{port} blocked from those addresses.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                         help=f"Port to block (default: {DEFAULT_PORT})")
    parser.add_argument("--url", default=DEFAULT_URL,
                         help="Feed URL returning one IP per line")
    parser.add_argument("--dry-run", action="store_true",
                         help="Fetch and parse the list without touching the firewall")
    args = parser.parse_args()

    if not is_admin():
        print("[!] This script must be run with administrator/root privileges.",
              file=sys.stderr)
        sys.exit(1)

    ips = fetch_ip_list(args.url)

    if args.dry_run:
        print(f"[dry-run] Would block {len(ips)} IPs on port {args.port}.")
        return

    system = platform.system()
    if system == "Linux":
        block_linux(ips, args.port)
    elif system == "Darwin":
        block_macos_pf(ips, args.port)
    elif system == "Windows":
        block_windows(ips, args.port)
    else:
        raise RuntimeError(f"Unsupported OS: {system}")


if __name__ == "__main__":
    main()