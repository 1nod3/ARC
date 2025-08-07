# ARC – Artifact Reuse Comparator

ARC (Artifact Reuse Comparator) is a static analysis tool for Windows PE files (executables and DLLs) that identifies code reuse across binaries. ARC disassembles files, extracts various artefacts (such as functions, basic blocks, API calls, and sliding-window fingerprints), stores them in an SQLite database, and then compares new binaries against previously analyzed ones. Detailed reports (in TXT and HTML formats) can be generated, and a control flow graph (CFG) visualization is available.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Dependencies and Installation](#dependencies-and-installation)
4. [Script Architecture](#script-architecture)
   - [Utility Functions](#utility-functions)
   - [Multiprocessing Helper](#multiprocessing-helper)
   - [Instruction Normalization & Fingerprinting](#instruction-normalization--fingerprinting)
   - [PE-specific Functions](#pe-specific-functions)
   - [Higher-Level Analysis](#higher-level-analysis)
   - [Control Flow Graph (CFG) Visualization](#control-flow-graph-cfg-visualization)
   - [Database Functions](#database-functions)
   - [Report Generation](#report-generation)
5. [Usage Instructions](#usage-instructions)
6. [Output explanation]
7. [Limitations](#limitations)
8. [Future Plans](#future-plans)
9. [License](#license)

---

## Overview

ARC – Artifact Reuse Comparator is designed for security researchers, reverse engineers, and malware analysts. It performs comprehensive static analysis of PE files, extracts code artefacts, and compares them across multiple binaries to uncover code reuse patterns. ARC’s modular design makes it extensible for future enhancements.

---

## Features

- Batch Analysis: Accepts a single file or a directory of PE files (.exe and .dll).
- Static Analysis:
  - Disassembly: Uses Capstone to disassemble the .text section.
  - Normalization: Standardizes instructions to abstract away specific registers or immediate values.
  - Function Extraction: Detects function boundaries and computes a SHA256 fingerprint for each function.
  - Basic Block Extraction: Groups instructions into basic blocks and computes fingerprints.
  - API Call Analysis: Extracts API call details by correlating disassembled call instructions with the PE import table.
  - Sliding-window Fingerprinting: Uses multiple techniques (SHA256, Simhash, and Winnowing) to compute fingerprints on sliding windows of instructions.
  - Entropy Calculation: Computes the Shannon entropy of binary data to detect potential obfuscation or packing.
- Database Storage: Stores analysis results in an SQLite database for reuse and matching.
- Similarity Matching: Compares new binary analysis against stored ones and calculates similarity ratios for:
  - Functions
  - Basic blocks
  - API calls
  - Sliding-window fingerprints
- Report Generation: Produces detailed reports in both TXT and HTML formats with an option for a tabular detailed view.
- CFG Visualization: Contains a function to build and display a control flow graph (CFG) using NetworkX and matplotlib.

---

## Dependencies and Installation

Ensure you have Python 3 installed. Install the required libraries using pip:

```bash
pip install capstone pefile simhash networkx matplotlib
```

The script uses the following major libraries:
- Capstone for disassembly.
- pefile for parsing PE file headers and sections.
- simhash for computing similarity fingerprints.
- NetworkX and matplotlib for CFG visualization.
- SQLite3 (bundled with Python) for database storage.

---

## Script Architecture

### Utility Functions

- `compute_entropy(data)`  
  Calculates the Shannon entropy of the provided data. Used to help determine if a file is obfuscated or packed.

- `detect_obfuscation(binary_data, threshold=7.5)`  
  Computes the entropy and logs whether it is above a given threshold, indicating potential obfuscation.

### Multiprocessing Helper

- `process_window(i, instructions, window_size)`  
  Processes a sliding window of instructions in parallel and computes SHA256, Simhash, and Winnowing fingerprints for that window.

### Instruction Normalization & Fingerprinting

- `improved_normalize_instruction(insn)`  
  Normalizes a disassembled instruction by converting it to lowercase and replacing immediate values and register names with placeholders. Supports both raw Capstone objects and serialized tuples.

- `compute_simhash_for_window(window)`  
  Computes the Simhash fingerprint for a window of normalized instructions.

- `compute_winnowing_fingerprint(window, k, w)`  
  Implements the Winnowing algorithm to create a fingerprint based on k-grams of normalized instruction tokens.

### PE-specific Functions

- `select_architecture(arch, pe)`  
  Chooses the correct Capstone architecture and mode based on input parameters and the PE header.

- `get_code_section(file_path)`  
  Parses the PE file and extracts the .text section, returning its binary data and starting address.

- `disassemble_code(code, base_addr, mode, arch)`  
  Disassembles the code using Capstone and returns a list of instructions.

### Higher-Level Analysis

- `extract_basic_blocks(instructions)`  
  Groups instructions into basic blocks based on branch targets. Supports both Capstone objects and serialized tuples.

- `analyze_basic_blocks(instructions)`  
  Computes a fingerprint for each basic block.

- `detect_function_boundaries(instructions)`  
  Uses heuristics (e.g., standard function prologues) to detect function boundaries.

- `extract_functions(instructions)`  
  Extracts functions based on detected boundaries and computes a SHA256 fingerprint for each function.

- `analyze_api_calls(instructions, pe)`  
  Extracts API call details by matching call instructions with the import table from the PE.

- `parallel_detect_reused_code(instructions, window_size)`  
  Runs a sliding-window analysis in parallel to compute additional fingerprints.

### CFG Visualization

- `build_cfg(instructions)`  
  Constructs a control flow graph (CFG) from the extracted basic blocks using NetworkX. The CFG can be visualized using matplotlib.

### Database Functions

- `init_db()`  
  Initializes the SQLite database and creates necessary tables (binaries, functions, api_calls, basic_blocks, sliding_windows). It also checks and adds the `func_hash` column to the functions table if missing.

- `store_analysis(conn, analysis)`  
  Stores the analysis results for a file into the database.

- `get_file_hash(conn, binary_id)`  
  Retrieves the MD5 hash (used as the unique identifier) for a given binary from the database.

- `match_analysis(conn, binary_id, analysis)`  
  Compares the current analysis with stored entries, calculating similarity ratios for each category (functions, basic blocks, API calls, sliding windows).

### Report Generation

- `generate_report(report_data, detailed)`  
  Generates TXT and HTML reports. When the `--detailed-report` flag is used, the reports include detailed, tabular data with counts, ratios, and matching artefacts.

### CFG Visualization (Optional)

- `build_cfg(instructions)`  
  (See above.) Use this function together with your preferred NetworkX visualization commands to display the CFG.

### Main Function

- `main()`  
  Handles command-line arguments, processes the files, performs analysis, stores results in the database, matches similarities, and generates final reports.

---

## Usage Instructions

1. Run the Script  
   To analyze a single file or directory:
   ```bash
   python arc_artifact_reuse_comparator.py /path/to/pe/files --arch x86 --window 5 --detailed-report
   ```
   Replace `/path/to/pe/files` with your file or directory path. Adjust the `--arch` and `--window` parameters as needed.

2. View the Reports  
   The script generates two report files (TXT and HTML) with unique filenames (based on timestamps). Open these files in a text editor or browser to review the analysis and matching results.

3. Visualize the CFG  
   To visualize the control flow graph for a binary, uncomment the following lines in the `main()` function:
   ```python
   # cfg = build_cfg(instructions)
   # visualize_cfg(cfg)
   ```
   Ensure your environment supports graphical display (or modify the function to save the plot as an image).

4. Database Considerations  
   ARC stores analysis results in an SQLite database named `analysis.db`. If you update the schema, delete or rename the existing database file to allow ARC to create a fresh one.

---

The tool generates two types of report outputs—a standard (summary) output and a detailed output. Here’s how to interpret them:

### Standard Output

- Per Binary Analysis:  
  For each PE file processed, the report lists its filename and provides a summary for each matching category:
  - Functions
  - Basic Block
  - API Calls
  - Sliding Windows (SHA256, Simhash, Winnowing)

- Match Summary:  
  For each category, it shows entries for each other binary (identified by its MD5 hash) that has matching artefacts. For each match, you will see:
  - Count: The number of artefacts (e.g., functions, basic blocks) that matched between the current binary and the other binary.
  - Ratio: A similarity ratio computed as the number of matching artefacts divided by the total number of artefacts of that type in the current binary.
  
This output gives you a quick view of which binaries share significant code similarities and to what extent.

### Detailed Output

When you run the tool with the `--detailed-report` flag, the report becomes more granular:
  
- Tabular Format:  
  In both the TXT and HTML reports, each category is presented in a table. The columns typically include:
  - Binary MD5: The unique identifier of the matching binary.
  - Count: How many artefacts matched.
  - Ratio: The computed similarity ratio.
  - Artefact Details: A list (comma-separated) of specific artefact identifiers such as:
    - For Functions: The start addresses of matching functions.
    - For Basic Blocks: The start addresses of matching basic blocks.
    - For API Calls: The call addresses and corresponding API details.
    - For Sliding Windows: The start addresses of the windows that generated matching fingerprints.

This detailed view lets you drill down into the exact pieces of code that were identified as reused, providing a deeper insight into the similarity and potential shared origin of code between binaries.

### Example

Imagine a simplified scenario:

- Standard Output:  
  ```
  Analysis Report for: sample.exe
  ----------------------------------------
  Functions Matches:
    Matches with Binary MD5 ABC123: Count=5, Ratio=0.45
  Basic Block Matches:
    Matches with Binary MD5 DEF456: Count=12, Ratio=0.35
  API Calls Matches:
    None
  Sliding Windows (SHA256) Matches:
    Matches with Binary MD5 ABC123: Count=20, Ratio=0.50
  ```

- Detailed Output:  
  In detailed mode, for the "Functions Matches" section, you might see a table like:
  
  | Binary MD5 | Count | Ratio | Artefact Details            |
  |------------|-------|-------|-----------------------------|
  | ABC123     | 5     | 0.45  | 0x401000, 0x402050, ...      |
  
  And similar tables for the other categories. The Artefact Details column lists the specific addresses (or call details) that contributed to the match.

This level of detail is especially useful when you need to investigate exactly which functions or blocks are reused across different binaries.

---

## Limitations

- Heuristic-Based Function Detection:  
  The tool uses simple heuristics to detect function boundaries. This approach might miss functions or produce false positives, especially in heavily obfuscated or optimized binaries.

- Architecture Support:  
  The tool is primarily designed for x86, ARM, and MIPS. Effectiveness may vary with different or less common architectures.

- Sliding-window Parameters:  
  The default sliding-window size may not be optimal for all binaries. Fine-tuning may be required for best results.

- Static Analysis Only:  
  ARC does not perform dynamic analysis, so it cannot capture runtime behavior or self-modifying code.

- Import Table Dependence for API Calls:  
  API call extraction relies on the PE import table, which may be incomplete or obfuscated in packed or heavily obfuscated binaries.

---

This documentation serves as a complete guide to ARC – Artifact Reuse Comparator, its features, architecture, usage, limitations, and future enhancements.
