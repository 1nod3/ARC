#!/usr/bin/env python3
"""
Advanced Batch Code Reuse Analyzer for PEEXE and PEDLL Files (MD5 Identifier, Detailed Report with Functions)

Features:
  • Accepts a single file or folder of files.
  • Processes only PE files (Windows executables and DLLs).
  • Performs static analysis:
      - Extracts the .text section from the PE.
      - Disassembles code using Capstone (supports x86, arm, mips).
      - Applies improved normalization of instructions.
      - Detects function boundaries and extracts functions (computing a SHA256 fingerprint for each).
      - Extracts API calls.
      - Extracts basic blocks and uses sliding-window analysis (SHA256, Simhash, Winnowing) for code reuse.
      - Computes file entropy for obfuscation detection.
  • Computes the MD5 hash of each PE file and uses it as the unique identifier.
  • Stores analysis results (including function fingerprints and PE type) in an optimized SQLite database.
  • When analyzing new files, compares them with previously stored analyses and reports matches
    (functions, basic blocks, API calls, sliding windows) using the MD5 hash as the key.
  • If the user passes --detailed-report, the report is presented in tabular form with full artefact details.
  • The report files are uniquely named with a timestamp.
  
Dependencies:
    pip install capstone pefile simhash networkx matplotlib
"""

import sys, os, re, math, hashlib, multiprocessing, sqlite3, datetime, logging
from collections import defaultdict

import networkx as nx
import matplotlib.pyplot as plt

# Set up basic logging.
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# --- External libraries ---
try:
    import pefile
except ImportError:
    pefile = None

from capstone import *
try:
    from simhash import Simhash
except ImportError:
    logging.error("Simhash library not found. Install it with: pip install simhash")
    sys.exit(1)

########################################
# Utility Functions for Entropy Calculation
########################################
def compute_entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = sum(- (count/len(data)) * math.log(count/len(data), 2) for count in freq.values())
    return ent

def detect_obfuscation(binary_data, threshold=7.5):
    ent = compute_entropy(binary_data)
    if ent > threshold:
        logging.info(f"High entropy detected: {ent:.2f} (above {threshold}). Possibly obfuscated/packed.")
    else:
        logging.info(f"Entropy: {ent:.2f}. Likely not obfuscated.")
    return ent

########################################
# Top-Level Helper Function for Multiprocessing
########################################
def process_window(i, instructions, window_size):
    """
    Compute fingerprints for a sliding window starting at index i.
    Expects instructions to be a list of tuples: (address, mnemonic, op_str).
    """
    window = instructions[i:i+window_size]
    norm = " ".join([improved_normalize_instruction(insn) for insn in window])
    sha_hash = hashlib.sha256(norm.encode('utf-8')).hexdigest()
    simhash_val = Simhash([improved_normalize_instruction(insn) for insn in window]).value
    simhash_val = simhash_val & ((1 << 63) - 1)  # limit to 63 bits
    winnowing_fp = compute_winnowing_fingerprint(window)
    return (sha_hash, simhash_val, winnowing_fp, window[0][0])  # window[0][0] is the address

########################################
# Instruction Normalization and Fingerprinting
########################################
def improved_normalize_instruction(insn):
    """
    Normalize an instruction by converting to lowercase, replacing immediate numeric
    values with 'IMM' and register names with 'REG'.
    Supports both tuple (address, mnemonic, op_str) and Capstone object.
    """
    if isinstance(insn, tuple):
        mnemonic, op_str = insn[1], insn[2]
    else:
        mnemonic = insn.mnemonic
        op_str = insn.op_str if insn.op_str is not None else ""
    text = (mnemonic + " " + op_str).lower()
    text = re.sub(r'0x[0-9a-f]+', 'IMM', text)
    text = re.sub(r'\b\d+\b', 'IMM', text)
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
        text = re.sub(r'\b' + reg + r'\b', 'REG', text)
    return re.sub(r'\s+', ' ', text).strip()

def compute_simhash_for_window(window):
    tokens = [improved_normalize_instruction(insn) for insn in window]
    return Simhash(tokens).value

def compute_winnowing_fingerprint(window, k=3, w=4):
    tokens = [improved_normalize_instruction(insn) for insn in window]
    n = len(tokens)
    if n < k:
        return None
    kgrams = [" ".join(tokens[i:i+k]) for i in range(n - k + 1)]
    hashes = [int(hashlib.sha256(kgram.encode('utf-8')).hexdigest(), 16) for kgram in kgrams]
    fingerprints = set()
    if len(hashes) < w:
        fingerprints.add(min(hashes))
    else:
        for i in range(len(hashes) - w + 1):
            fingerprints.add(min(hashes[i:i+w]))
    return hashlib.sha256("".join(map(str, sorted(fingerprints))).encode('utf-8')).hexdigest()

########################################
# PE-specific Functions
########################################
def select_architecture(arch="x86", pe=None):
    if arch.lower() == "x86":
        if pe and hasattr(pe, 'OPTIONAL_HEADER'):
            return (CS_ARCH_X86, CS_MODE_64) if getattr(pe.OPTIONAL_HEADER, 'Magic', 0) == 0x20b else (CS_ARCH_X86, CS_MODE_32)
        else:
            return CS_ARCH_X86, CS_MODE_32
    elif arch.lower() == "arm":
        from capstone import CS_MODE_ARM
        return CS_ARCH_ARM, CS_MODE_ARM
    elif arch.lower() == "mips":
        from capstone import CS_MODE_MIPS32
        return CS_ARCH_MIPS, CS_MODE_MIPS32
    else:
        logging.warning(f"Unsupported architecture: {arch}. Defaulting to x86 32-bit.")
        return CS_ARCH_X86, CS_MODE_32

def get_code_section(file_path):
    if not pefile:
        logging.error("pefile module not installed, cannot process PE files.")
        sys.exit(1)
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        logging.error(f"Error parsing PE file {file_path}: {e}")
        return None, None, None
    for section in pe.sections:
        if b'.text' in section.Name:
            code = section.get_data()
            addr = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
            return code, addr, pe
    logging.error(f"PE file {file_path} does not contain a .text section.")
    return None, None, None

def disassemble_code(code, base_addr, mode, arch="x86"):
    try:
        cs = Cs(*select_architecture(arch)) if arch.lower() in ["arm", "mips"] else Cs(CS_ARCH_X86, mode)
        cs.detail = True
        return [insn for insn in cs.disasm(code, base_addr)]
    except Exception as e:
        logging.error(f"Disassembly failed: {e}")
        return []

########################################
# Higher-Level Analysis: Basic Blocks, Functions, API Calls
########################################
def extract_basic_blocks(instructions):
    """
    Extract basic blocks from instructions. Supports both Capstone objects and serialized tuples.
    """
    branch_mnemonics = {"jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "call", "ret"}
    branch_targets = set()
    for insn in instructions:
        try:
            if isinstance(insn, tuple):
                mnemonic = insn[1]
                op_str = insn[2]
                addr = insn[0]
            else:
                mnemonic = insn.mnemonic
                op_str = insn.op_str if insn.op_str is not None else ""
                addr = insn.address
            if mnemonic in branch_mnemonics:
                target = int(op_str.split()[0], 0)
                branch_targets.add(target)
        except Exception:
            continue
    blocks = []
    current_block = []
    for insn in instructions:
        try:
            if isinstance(insn, tuple):
                addr = insn[0]
                mnemonic = insn[1]
            else:
                addr = insn.address
                mnemonic = insn.mnemonic
        except Exception:
            continue
        if addr in branch_targets and current_block:
            blocks.append(current_block)
            current_block = []
        current_block.append(insn)
        if mnemonic in branch_mnemonics:
            blocks.append(current_block)
            current_block = []
    if current_block:
        blocks.append(current_block)
    return blocks

def analyze_basic_blocks(instructions):
    blocks = extract_basic_blocks(instructions)
    block_list = []
    for block in blocks:
        if not block:
            continue
        if isinstance(block[0], tuple):
            addr = block[0][0]
        else:
            addr = block[0].address
        tokens = [improved_normalize_instruction(insn) for insn in block]
        block_hash = Simhash(tokens).value & ((1 << 63) - 1)
        block_list.append((addr, block_hash))
    return block_list

def detect_function_boundaries(instructions):
    boundaries = set()
    for i in range(len(instructions) - 1):
        try:
            if (instructions[i].mnemonic == "push" and "ebp" in instructions[i].op_str.lower() and
                instructions[i+1].mnemonic == "mov" and "ebp" in instructions[i+1].op_str.lower() and
                "esp" in instructions[i+1].op_str.lower()):
                boundaries.add(instructions[i].address)
            if instructions[i].mnemonic == "call":
                target = int(instructions[i].op_str.split()[0], 0)
                boundaries.add(target)
        except Exception:
            continue
    return sorted(boundaries)

def extract_functions(instructions):
    boundaries = detect_function_boundaries(instructions)
    if not boundaries:
        return []
    instructions_sorted = sorted(instructions, key=lambda insn: insn.address)
    functions = []
    for i, start in enumerate(boundaries):
        if i + 1 < len(boundaries):
            func_instrs = [insn for insn in instructions_sorted if start <= insn.address < boundaries[i+1]]
        else:
            func_instrs = [insn for insn in instructions_sorted if insn.address >= start]
        if not func_instrs:
            continue
        normalized = " ".join(improved_normalize_instruction(insn) for insn in func_instrs)
        func_hash = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
        functions.append((start, func_hash))
    return functions

def analyze_api_calls(instructions, pe):
    api_calls = []
    if pe is None or not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return api_calls
    imp_map = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.address:
                imp_map[imp.address] = imp.name.decode() if imp.name else ""
    for insn in instructions:
        if insn.mnemonic == "call":
            try:
                target = int(insn.op_str.split()[0], 0)
                api_calls.append((insn.address, target, imp_map.get(target, "Unknown")))
            except Exception:
                continue
    return api_calls

def parallel_detect_reused_code(instructions, window_size=5):
    results = []
    try:
        args_list = [(i, instructions, window_size) for i in range(len(instructions) - window_size + 1)]
        with multiprocessing.Pool() as pool:
            results = pool.starmap(process_window, args_list)
    except Exception as e:
        logging.error(f"Error during parallel processing: {e}")
        results = []
    sha_dict, simhash_dict, winnowing_dict = defaultdict(list), defaultdict(list), defaultdict(list)
    for sha_hash, simhash_val, winnowing_fp, start_addr in results:
        sha_dict[sha_hash].append(start_addr)
        simhash_dict[simhash_val].append(start_addr)
        if winnowing_fp:
            winnowing_dict[winnowing_fp].append(start_addr)
    reused_sha = {h: addrs for h, addrs in sha_dict.items() if len(addrs) > 1}
    reused_simhash = {h: addrs for h, addrs in simhash_dict.items() if len(addrs) > 1}
    reused_winnowing = {h: addrs for h, addrs in winnowing_dict.items() if len(addrs) > 1}
    return reused_sha, reused_simhash, reused_winnowing

########################################
# CFG Visualization Function (Optional)
########################################
def build_cfg(instructions):
    """
    Build a simple control flow graph (CFG) from the basic blocks.
    Supports both Capstone objects and serialized tuples.
    """
    blocks = extract_basic_blocks(instructions)
    cfg = nx.DiGraph()
    block_dict = {}
    for block in blocks:
        if block:
            if isinstance(block[0], tuple):
                addr = block[0][0]
            else:
                addr = block[0].address
            cfg.add_node(addr, instructions=block)
            block_dict[addr] = block
    for block in blocks:
        if block:
            if isinstance(block[0], tuple):
                start_addr = block[0][0]
                last_insn = block[-1]
                mnemonic = last_insn[1]
                op_str = last_insn[2]
            else:
                start_addr = block[0].address
                last_insn = block[-1]
                mnemonic = last_insn.mnemonic
                op_str = last_insn.op_str if last_insn.op_str is not None else ""
            branch_mnemonics = {"jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "call"}
            try:
                if mnemonic in branch_mnemonics:
                    target = int(op_str.split()[0], 0)
                    if target in block_dict:
                        cfg.add_edge(start_addr, target)
            except Exception:
                pass
            next_blocks = [addr for addr in block_dict.keys() if addr > start_addr]
            if next_blocks:
                cfg.add_edge(start_addr, min(next_blocks))
    return cfg

########################################
# Database Functions (SQLite)
########################################
DB_PATH = "analysis.db"
MIN_MATCH_THRESHOLD = 3

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode = WAL;")
        cur.execute("PRAGMA synchronous = NORMAL;")
        cur.executescript("""
        CREATE TABLE IF NOT EXISTS binaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            file_hash TEXT,
            entropy REAL,
            arch TEXT,
            analysis_date TEXT,
            pe_type TEXT
        );
        CREATE TABLE IF NOT EXISTS functions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id INTEGER,
            address INTEGER,
            func_hash TEXT,
            FOREIGN KEY(binary_id) REFERENCES binaries(id)
        );
        CREATE TABLE IF NOT EXISTS api_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id INTEGER,
            call_address INTEGER,
            target INTEGER,
            api_name TEXT,
            FOREIGN KEY(binary_id) REFERENCES binaries(id)
        );
        CREATE TABLE IF NOT EXISTS basic_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id INTEGER,
            start_address INTEGER,
            simhash INTEGER,
            FOREIGN KEY(binary_id) REFERENCES binaries(id)
        );
        CREATE TABLE IF NOT EXISTS sliding_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id INTEGER,
            type TEXT,
            fingerprint TEXT,
            start_address INTEGER,
            FOREIGN KEY(binary_id) REFERENCES binaries(id)
        );
        CREATE INDEX IF NOT EXISTS idx_basic_blocks_simhash ON basic_blocks(simhash);
        CREATE INDEX IF NOT EXISTS idx_api_calls_name ON api_calls(api_name);
        CREATE INDEX IF NOT EXISTS idx_sliding_windows_fp ON sliding_windows(fingerprint);
        """)
        conn.commit()
        # Ensure the functions table has the func_hash column
        cur.execute("PRAGMA table_info(functions)")
        cols = [row[1] for row in cur.fetchall()]
        if "func_hash" not in cols:
            cur.execute("ALTER TABLE functions ADD COLUMN func_hash TEXT")
            conn.commit()
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        sys.exit(1)

def store_analysis(conn, analysis):
    try:
        cur = conn.cursor()
        now = datetime.datetime.now().isoformat()
        cur.execute("INSERT INTO binaries (file_path, file_hash, entropy, arch, pe_type, analysis_date) VALUES (?,?,?,?,?,?)",
                    (analysis["file_path"], analysis["file_hash"], analysis["entropy"], analysis["arch"], analysis["pe_type"], now))
        binary_id = cur.lastrowid
        if analysis.get("functions"):
            cur.executemany("INSERT INTO functions (binary_id, address, func_hash) VALUES (?,?,?)",
                            [(binary_id, addr, func_hash) for addr, func_hash in analysis["functions"]])
        if analysis.get("api_calls"):
            cur.executemany("INSERT INTO api_calls (binary_id, call_address, target, api_name) VALUES (?,?,?,?)",
                            [(binary_id, call_addr, target, api_name) for call_addr, target, api_name in analysis["api_calls"]])
        if analysis.get("basic_blocks"):
            cur.executemany("INSERT INTO basic_blocks (binary_id, start_address, simhash) VALUES (?,?,?)",
                            [(binary_id, addr, simhash_val & ((1 << 63) - 1)) for addr, simhash_val in analysis["basic_blocks"]])
        sw_data = []
        for typ in ["sha256", "simhash", "winnowing"]:
            for fingerprint, addr in analysis.get("sliding_windows", {}).get(typ, []):
                sw_data.append((binary_id, typ, fingerprint, addr))
        if sw_data:
            cur.executemany("INSERT INTO sliding_windows (binary_id, type, fingerprint, start_address) VALUES (?,?,?,?)",
                            sw_data)
        conn.commit()
        return binary_id
    except sqlite3.Error as e:
        logging.error(f"Error storing analysis for {analysis.get('file_path')}: {e}")
        conn.rollback()
        return None

def get_file_hash(conn, binary_id):
    cur = conn.cursor()
    cur.execute("SELECT file_hash FROM binaries WHERE id = ?", (binary_id,))
    row = cur.fetchone()
    return row[0] if row else None

def match_analysis(conn, binary_id, analysis):
    cur = conn.cursor()
    matches = {
        "basic_blocks": {},
        "api_calls": {},
        "sliding_windows_sha256": {},
        "sliding_windows_simhash": {},
        "sliding_windows_winnowing": {},
        "functions": {}
    }
    total_bb = len(analysis.get("basic_blocks", []))
    total_api = len(analysis.get("api_calls", []))
    total_sw = {"sha256": len(analysis.get("sliding_windows", {}).get("sha256", [])),
                "simhash": len(analysis.get("sliding_windows", {}).get("simhash", [])),
                "winnowing": len(analysis.get("sliding_windows", {}).get("winnowing", []))}
    total_func = len(analysis.get("functions", []))
    
    # Basic Blocks Matching
    for _, simhash_val in analysis.get("basic_blocks", []):
        try:
            cur.execute("SELECT binary_id, start_address FROM basic_blocks WHERE simhash = ? AND binary_id != ?", (simhash_val, binary_id))
            for other_id, addr in cur.fetchall():
                if other_id not in matches["basic_blocks"]:
                    matches["basic_blocks"][other_id] = {'count': 0, 'addresses': []}
                matches["basic_blocks"][other_id]['count'] += 1
                matches["basic_blocks"][other_id]['addresses'].append(addr)
        except sqlite3.Error:
            continue

    # API Calls Matching
    for _, _, api_name in analysis.get("api_calls", []):
        try:
            cur.execute("SELECT binary_id, call_address, target, api_name FROM api_calls WHERE api_name = ? AND binary_id != ?", (api_name, binary_id))
            for other_id, call_addr, target, api in cur.fetchall():
                if other_id not in matches["api_calls"]:
                    matches["api_calls"][other_id] = {'count': 0, 'calls': []}
                matches["api_calls"][other_id]['count'] += 1
                matches["api_calls"][other_id]['calls'].append((call_addr, target, api))
        except sqlite3.Error:
            continue

    # Sliding Windows Matching
    for typ, key in [("sha256", "sliding_windows_sha256"),
                     ("simhash", "sliding_windows_simhash"),
                     ("winnowing", "sliding_windows_winnowing")]:
        for fingerprint, _ in analysis.get("sliding_windows", {}).get(typ, []):
            try:
                cur.execute("SELECT binary_id, start_address FROM sliding_windows WHERE type = ? AND fingerprint = ? AND binary_id != ?", 
                            (typ, fingerprint, binary_id))
                for other_id, addr in cur.fetchall():
                    if other_id not in matches[key]:
                        matches[key][other_id] = {'count': 0, 'addresses': []}
                    matches[key][other_id]['count'] += 1
                    matches[key][other_id]['addresses'].append(addr)
            except sqlite3.Error:
                continue

    # Functions Matching
    for addr, func_hash in analysis.get("functions", []):
        try:
            cur.execute("SELECT binary_id, address FROM functions WHERE func_hash = ? AND binary_id != ?", (func_hash, binary_id))
            for other_id, faddr in cur.fetchall():
                if other_id not in matches["functions"]:
                    matches["functions"][other_id] = {'count': 0, 'addresses': []}
                matches["functions"][other_id]['count'] += 1
                matches["functions"][other_id]['addresses'].append(faddr)
        except sqlite3.Error:
            continue

    match_ratios = {}
    for cat, match_dict in matches.items():
        ratio_dict = {}
        for other_id, data in match_dict.items():
            if cat == "basic_blocks":
                total = total_bb
            elif cat == "api_calls":
                total = total_api
            elif cat == "functions":
                total = total_func
            else:
                total = total_sw[cat.split("_")[-1]]
            ratio = data['count'] / total if total else 0
            if data['count'] >= MIN_MATCH_THRESHOLD:
                other_md5 = get_file_hash(conn, other_id)
                if other_md5:
                    data['ratio'] = round(ratio, 2)
                    ratio_dict[other_md5] = data
        sorted_ratio = dict(sorted(ratio_dict.items(), key=lambda x: x[1]["ratio"], reverse=True))
        match_ratios[cat] = sorted_ratio
    return match_ratios

########################################
# Report Generation Functions
########################################
def generate_report(report_data, detailed=False):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = f"report_{ts}.txt"
    html_file = f"report_{ts}.html"
    
    try:
        with open(txt_file, "w") as f:
            for file_path, details in report_data.items():
                f.write(f"Analysis Report for: {file_path}\n")
                f.write("-" * 50 + "\n")
                for cat, matches in details.items():
                    f.write(f"{cat} Matches:\n")
                    if matches:
                        if detailed:
                            f.write(f"{'MD5':<40} {'Count':<10} {'Ratio':<10} Artefacts\n")
                            for other_md5, data in matches.items():
                                artefacts = ", ".join(str(x) for x in data.get('addresses', data.get('calls', [])))
                                f.write(f"{other_md5:<40} {data['count']:<10} {data['ratio']:<10} {artefacts}\n")
                        else:
                            for other_md5, data in matches.items():
                                f.write(f"  Matches with Binary MD5 {other_md5}: Count={data['count']}, Ratio={data['ratio']}\n")
                    else:
                        f.write("  None\n")
                f.write("\n")
        with open(html_file, "w") as f:
            f.write("<html><head><title>Code Reuse Analysis Report</title></head><body>\n")
            f.write("<h1>Code Reuse Analysis Report</h1>\n")
            for file_path, details in report_data.items():
                f.write(f"<h2>Analysis Report for: {file_path}</h2>\n")
                for cat, matches in details.items():
                    f.write(f"<h3>{cat} Matches:</h3>\n")
                    if matches:
                        if detailed:
                            f.write("<table border='1' cellpadding='5'>")
                            f.write("<tr><th>Binary MD5</th><th>Count</th><th>Ratio</th><th>Artefact Details</th></tr>")
                            for other_md5, data in matches.items():
                                artefacts = ", ".join(str(x) for x in data.get('addresses', data.get('calls', [])))
                                f.write(f"<tr><td>{other_md5}</td><td>{data['count']}</td><td>{data['ratio']}</td><td>{artefacts}</td></tr>")
                            f.write("</table>")
                        else:
                            f.write("<ul>")
                            for other_md5, data in matches.items():
                                f.write(f"<li>Binary MD5 {other_md5}: Count={data['count']}, Ratio={data['ratio']}</li>")
                            f.write("</ul>")
                    else:
                        f.write("None")
                f.write("<hr>")
            f.write("</body></html>")
        logging.info(f"Report generated: {html_file} and {txt_file}")
    except Exception as e:
        logging.error(f"Error generating report: {e}")

########################################
# CFG Visualization Function (Optional)
########################################
def build_cfg(instructions):
    """
    Build a simple control flow graph (CFG) from the basic blocks.
    Supports both Capstone objects and serialized tuples.
    """
    blocks = extract_basic_blocks(instructions)
    cfg = nx.DiGraph()
    block_dict = {}
    for block in blocks:
        if block:
            if isinstance(block[0], tuple):
                addr = block[0][0]
            else:
                addr = block[0].address
            cfg.add_node(addr, instructions=block)
            block_dict[addr] = block
    for block in blocks:
        if block:
            if isinstance(block[0], tuple):
                start_addr = block[0][0]
                last_insn = block[-1]
                mnemonic = last_insn[1]
                op_str = last_insn[2]
            else:
                start_addr = block[0].address
                last_insn = block[-1]
                mnemonic = last_insn.mnemonic
                op_str = last_insn.op_str if last_insn.op_str is not None else ""
            branch_mnemonics = {"jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "call"}
            try:
                if mnemonic in branch_mnemonics:
                    target = int(op_str.split()[0], 0)
                    if target in block_dict:
                        cfg.add_edge(start_addr, target)
            except Exception:
                pass
            next_blocks = [addr for addr in block_dict.keys() if addr > start_addr]
            if next_blocks:
                cfg.add_edge(start_addr, min(next_blocks))
    return cfg

########################################
# Main Function: Process PE Files Only
########################################
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Batch Code Reuse Analyzer for PEEXE and PEDLL Files (MD5 Identifier)")
    parser.add_argument("input_path", help="Path to file or folder of files")
    parser.add_argument("--arch", default="x86", help="Architecture (x86, arm, mips). Default: x86")
    parser.add_argument("--window", type=int, default=5, help="Sliding window size. Default: 5")
    parser.add_argument("--detailed-report", action="store_true", help="Generate detailed tabular report with all artefact details.")
    args = parser.parse_args()

    conn = init_db()
    input_path = args.input_path
    file_list = []
    if os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for name in files:
                file_list.append(os.path.join(root, name))
    else:
        file_list = [input_path]

    report_data = {}

    for file_path in file_list:
        if not file_path.lower().endswith((".exe", ".dll")):
            logging.info(f"Skipping non-PE file: {file_path}")
            continue

        logging.info(f"=== Processing {file_path} ===")
        try:
            with open(file_path, "rb") as f:
                binary_data = f.read()
        except Exception as e:
            logging.error(f"Failed to read {file_path}: {e}")
            continue

        file_hash = hashlib.md5(binary_data).hexdigest()
        entropy = detect_obfuscation(binary_data)
        code, base_addr, pe = get_code_section(file_path)
        if code is None:
            logging.error(f"Skipping file {file_path} due to PE extraction errors.")
            continue
        arch, mode = select_architecture(args.arch, pe=pe)
        instructions = disassemble_code(code, base_addr, mode, arch=args.arch)
        if not instructions:
            logging.error(f"Disassembly failed for {file_path}. Skipping.")
            continue
        logging.info(f"Disassembled {len(instructions)} instructions.")

        serialized_instructions = [(insn.address, insn.mnemonic, insn.op_str if insn.op_str else "") for insn in instructions]

        functions = extract_functions(instructions)
        api_calls = analyze_api_calls(instructions, pe)
        basic_blocks = analyze_basic_blocks(instructions)
        reused_sha, reused_simhash, reused_winnowing = parallel_detect_reused_code(serialized_instructions, args.window)
        sliding_windows = {
            "sha256": [(fp, addr) for fp, addrs in reused_sha.items() for addr in addrs],
            "simhash": [(str(fp), addr) for fp, addrs in reused_simhash.items() for addr in addrs],
            "winnowing": [(fp, addr) for fp, addrs in reused_winnowing.items() for addr in addrs]
        }
        pe_type = "PEDLL" if (pe.FILE_HEADER.Characteristics & 0x2000) else "PEEXE"
        analysis = {
            "file_path": file_path,
            "file_hash": file_hash,
            "entropy": entropy,
            "arch": args.arch,
            "pe_type": pe_type,
            "functions": functions,
            "api_calls": api_calls,
            "basic_blocks": basic_blocks,
            "sliding_windows": sliding_windows
        }
        binary_id = store_analysis(conn, analysis)
        if binary_id is None:
            continue
        logging.info(f"Stored analysis for binary MD5 {file_hash}")
        matches = match_analysis(conn, binary_id, analysis)
        report_data[file_path] = {
            "Functions": matches.get("functions", {}),
            "Basic Block": matches.get("basic_blocks", {}),
            "API Calls": matches.get("api_calls", {}),
            "Sliding Windows (SHA256)": matches.get("sliding_windows_sha256", {}),
            "Sliding Windows (Simhash)": matches.get("sliding_windows_simhash", {}),
            "Sliding Windows (Winnowing)": matches.get("sliding_windows_winnowing", {})
        }
        # To visualize the CFG, uncomment the following lines:
        # cfg = build_cfg(instructions)
        # visualize_cfg(cfg)

    generate_report(report_data, detailed=args.detailed_report)
    conn.close()
    print("Report generated. Check the uniquely named report files in the current directory.")

if __name__ == '__main__':
    main()

