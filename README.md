# strx

`strx` — **Strings Extended** — is a high-performance, security-oriented string extraction and triage tool for binaries, memory dumps, firmware images, forensic artifacts, and other binary data.

It combines traditional string extraction with encoding detection, IoC classification, smart decoding, dictionary matching, heuristic scoring, and structured output.

```text
binary / memory dump / firmware
              │
              ▼
        string extraction
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
    ASCII    UTF-8    UTF-16
                       LE / BE
              │
              ▼
       smart decoding
        Base64 / Hex
              │
              ▼
        classification
     URLs · IPs · hashes
     e-mails · keys · code
              │
              ▼
          scoring
              │
        ┌─────┴─────┐
        ▼           ▼
     terminal      JSON
```

## Why strx?

Traditional tools such as `strings` are excellent at extracting printable character sequences from binary data.

During security research and digital forensics, however, extraction is often only the first step.

Interesting artifacts may include:

- URLs and network indicators
- IPv4 and IPv6 addresses
- e-mail addresses
- cryptographic hashes
- private-key markers
- encoded configuration data
- Base64 or hexadecimal payloads
- code fragments
- application-specific keywords
- strings near suspicious binary structures

`strx` performs this lightweight triage directly during extraction while preserving the original byte location of every candidate.

It is designed to answer not only:

> What strings exist in this file?

but also:

> Which strings are likely to be interesting?

---

## Features

### High-performance input handling

Regular files are accessed using memory mapping through [`memmap2`](https://crates.io/crates/memmap2).

This allows `strx` to inspect large files without first copying the complete input into another buffer.

Input can also be supplied through `stdin`.

```bash
strx sample.bin
```

```bash
cat sample.bin | strx
```

---

### Multiple encodings

`strx` can extract strings using:

| Encoding | Supported |
|---|---:|
| ASCII | Yes |
| UTF-8 | Yes |
| UTF-16 Little Endian | Yes |
| UTF-16 Big Endian | Yes |

UTF-16 extraction checks both possible byte alignments so embedded strings do not have to begin at an even file offset.

Original byte offsets are retained regardless of the detected encoding.

---

### IoC detection

Extracted strings can automatically be classified as security-relevant artifacts.

Built-in tags include:

| Tag | Description |
|---|---|
| `IPv4` | IPv4 address |
| `IPv6` | IPv6 address |
| `URL` | URL |
| `Email` | E-mail address |
| `MD5` | MD5 hash |
| `SHA1` | SHA-1 hash |
| `SHA256` | SHA-256 hash |
| `CryptoKey` | Cryptographic key marker |
| `Base64` | Successfully decoded Base64 |
| `Hex` | Successfully decoded hexadecimal content |
| `Dict` | Dictionary match |
| `Fuzzy` | Fuzzy dictionary match |
| `Regex` | User-supplied regular-expression match |
| `Code` | Possible source-code fragment |
| `AI` | AI/model-related token or marker |
| `HighEntropy` | High-entropy content |
| `LowEntropy` | Low-entropy content |

---

### Smart decoding

`strx` can inspect strings that resemble Base64 or hexadecimal data.

For example:

```text
Input:

aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGk=
```

may produce:

```text
Original:
aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGk=

Decoded:
https://example.com/api

Tags:
[Base64] [URL]
```

The original candidate is never replaced.

Its:

- original bytes
- byte offset
- original encoded representation
- original byte length

remain unchanged.

Decoded content is treated as derived information.

This distinction is important for reproducible forensic analysis.

---

### Dictionary matching

Custom dictionaries can be supplied with `--dict`.

```bash
strx --dict keywords.txt sample.bin
```

Multiple dictionaries can be used:

```bash
strx \
    --dict malware-terms.txt \
    --dict protocol-terms.txt \
    sample.bin
```

Exact matching uses Aho-Corasick multi-pattern search.

Optional fuzzy matching uses bounded Levenshtein distance:

```bash
strx \
    --dict keywords.txt \
    --fuzzy \
    sample.bin
```

Fuzzy matching is intentionally optional because it is significantly more expensive than exact matching.

---

### Custom regular expressions

Additional patterns can be supplied from the command line:

```bash
strx \
    --regex 'CVE-[0-9]{4}-[0-9]+' \
    sample.bin
```

Multiple expressions can be specified:

```bash
strx \
    --regex 'CVE-[0-9]{4}-[0-9]+' \
    --regex 'api[_-]?key' \
    sample.bin
```

Matches are tagged separately from dictionary matches.

---

### Heuristic scoring

Each extracted string receives a score indicating how potentially interesting it may be.

The score considers factors such as:

```text
string length
IoC matches
dictionary matches
decoded content
code-like structures
cryptographic material
hashes
entropy
```

Scores are intended for **triage and ranking**, not as a security verdict.

Sort results by score:

```bash
strx --sort score sample.bin
```

---

### Context hex dump

Use `-C` or `--context` to inspect bytes surrounding a candidate.

```bash
strx -C 16 sample.bin
```

Example:

```text
00012f40 [URL] http://example.com

  00012f30  00 01 ff 20 43 46 47 00 68 74 74 70 3a 2f 2f 65  |... CFG.http://e|
  00012f40  78 61 6d 70 6c 65 2e 63 6f 6d 00 5a 18 00 00 00  |xample.com.Z....|
```

The context is calculated around the complete candidate rather than only its first byte.

---

### JSON output

For scripting and automated analysis:

```bash
strx --json sample.bin
```

Example:

```json
[
  {
    "offset": 123456,
    "byte_length": 32,
    "char_length": 32,
    "encoding": "ASCII",
    "score": 81.2,
    "tags": [
      "Base64",
      "URL"
    ],
    "content": "aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGk=",
    "derived_content": "https://example.com/api"
  }
]
```

JSON output never contains ANSI terminal escape sequences.

---

## Installation

### Build from source

A recent stable Rust toolchain is required.

```bash
git clone https://github.com/MichaelWeissDEV/strx.git
cd strx

cargo build --release
```

The resulting binary is located at:

```text
target/release/strx
```

Optionally copy it into a directory contained in your `PATH`.

---

## Quick Start

Extract strings from a binary:

```bash
strx sample.bin
```

Only strings containing at least eight characters:

```bash
strx --min 8 sample.bin
```

Restrict the maximum length:

```bash
strx --min 4 --max 128 sample.bin
```

Inspect a specific byte range:

```bash
strx \
    --start 0x1000 \
    --end 0x8000 \
    sample.bin
```

Sort by score:

```bash
strx --sort score sample.bin
```

Sort by length:

```bash
strx --sort length-desc sample.bin
```

Use dictionary matching:

```bash
strx \
    --dict indicators.txt \
    sample.bin
```

Enable fuzzy matching:

```bash
strx \
    --dict indicators.txt \
    --fuzzy \
    sample.bin
```

Show surrounding bytes:

```bash
strx -C 32 sample.bin
```

Produce JSON:

```bash
strx --json sample.bin
```

Read from stdin:

```bash
cat sample.bin | strx
```

Use extraction without heuristic analysis:

```bash
strx --raw sample.bin
```

Show only a specific classification:

```bash
strx --tag url sample.bin
```

Exclude high-entropy candidates:

```bash
strx --exclude-tag high-entropy sample.bin
```

---

## Security Research Examples

### Malware triage

Rank potentially interesting strings:

```bash
strx \
    --sort score \
    -C 16 \
    malware.bin
```

Search using malware-analysis vocabulary:

```bash
strx \
    --dict malware-terms.txt \
    --sort score \
    malware.bin
```

---

### Firmware analysis

Extract long strings and inspect nearby binary data:

```bash
strx \
    --min 6 \
    -C 32 \
    firmware.bin
```

Search for network-related patterns:

```bash
strx \
    --tag url \
    firmware.bin
```

```bash
strx \
    --tag ipv4 \
    firmware.bin
```

---

### Memory dump triage

Process large memory dumps using memory-mapped I/O:

```bash
strx \
    --sort score \
    memory.raw
```

Search for application-specific strings:

```bash
strx \
    --regex '(token|secret|password|authorization)' \
    memory.raw
```

---

### Reverse engineering

Inspect strings only inside a region:

```bash
strx \
    --start 0x401000 \
    --end 0x480000 \
    -C 16 \
    program.bin
```

---

## CLI

Run:

```bash
strx --help
```

Core options:

```text
Usage:
  strx [OPTIONS] [INPUT]

Arguments:
  [INPUT]
      Input file.
      If omitted or "-", input is read from stdin.

Options:
  -r, --raw
      Skip heuristic classification.

  -n, --min <N>
      Minimum extracted string length.
      Default: 4.

  -x, --max <N>
      Maximum extracted string length.

  -S, --start <OFFSET>
      Start scanning at OFFSET.
      Decimal and 0x-prefixed hexadecimal values are supported.

  -E, --end <OFFSET>
      Stop scanning at OFFSET.

  -d, --dict <FILE>
      Load a dictionary.
      May be supplied multiple times.

  -e, --regex <PATTERN>
      Add a custom regular expression.
      May be supplied multiple times.

  -f, --fuzzy
      Enable fuzzy dictionary matching.

  -s, --sort <ORDER>
      Sorting mode.

      Values:
        offset
        length-asc
        length-desc
        score
        alphabetical

  -C, --context <BYTES>
      Show BYTES before and after the complete candidate.

      --json
      Produce JSON output.

      --show-encoding
      Display the detected encoding.

      --tag <TAG>
      Require a tag.
      May be supplied multiple times.

      --exclude-tag <TAG>
      Exclude candidates containing a tag.

  -q, --quiet
      Suppress normal output.

  -v, --verbose
      Display additional processing information.

  -h, --help
      Print help.

  -V, --version
      Print version.
```

The exact command-line interface is defined by `strx --help` and should be considered authoritative.

---

## Architecture

The project is split into independent components:

```text
src/
├── cli.rs          command-line parsing
├── extract.rs      string extraction engine
├── heuristics.rs   classification and smart decoding
├── io.rs           mmap and input handling
├── output.rs       terminal and JSON output
├── scoring.rs      ranking and sorting
├── types.rs        shared data structures
├── lib.rs          library interface
└── main.rs         CLI pipeline
```

The processing pipeline is conceptually:

```text
InputSource
    │
    ▼
Extraction Engine
    │
    ▼
StringCandidate
    │
    ▼
Decode / Normalize
    │
    ├── original content
    └── derived content
            │
            ▼
      Heuristic Pipeline
            │
            ▼
       AnnotatedString
            │
            ▼
       Scoring Engine
            │
            ▼
        Sort / Filter
            │
       ┌────┴────┐
       ▼         ▼
    Terminal    JSON
```

---

## Evidence Preservation

`strx` is designed for security research and forensic workflows where reproducibility matters.

A decoding or heuristic step must therefore never destroy information about the underlying file.

A candidate always retains its relationship to:

```text
original input
original byte offset
original byte length
detected encoding
```

Derived data such as decoded Base64 is additional metadata and does not replace the original evidence.

---

## Performance

`strx` is designed around several performance principles:

```text
memory-mapped regular files
slice-based processing
minimal copying
offset + length candidate references
precompiled regular expressions
Aho-Corasick dictionary matching
bounded fuzzy matching
single-pass extraction where practical
```

The heuristic pipeline is more computationally expensive than traditional raw string extraction.

For workloads where only extraction is required:

```bash
strx --raw sample.bin
```

Benchmark numbers should only be added to this section once they have been measured reproducibly on representative datasets.

---

## Development

Format the project:

```bash
cargo fmt --all
```

Check formatting:

```bash
cargo fmt --all -- --check
```

Run Clippy:

```bash
cargo clippy \
    --all-targets \
    --all-features \
    -- \
    -D warnings
```

Run tests:

```bash
cargo test \
    --all-targets \
    --all-features
```

Build an optimized binary:

```bash
cargo build --release
```

---

## Testing

Extraction code is security-relevant parser code and should be treated accordingly.

Tests should cover at least:

```text
ASCII extraction
UTF-8 validation
UTF-16LE
UTF-16BE
odd UTF-16 alignment
invalid encoding sequences
minimum and maximum lengths
start/end ranges
absolute offsets
EOF candidates
embedded NUL bytes
dictionary matching
fuzzy matching
Base64 decoding
hex decoding
IoC recognition
context boundaries
JSON serialization
```

The extraction engine is also suitable for fuzz testing.

Important invariants include:

```text
no panics for arbitrary input
offset + byte_length <= input length
no integer overflow
all returned ranges are valid
invalid encodings never create invalid memory accesses
```

---

## Limitations

`strx` is not intended to replace a full reverse-engineering, malware-analysis, or forensic framework.

Its heuristics are intentionally lightweight.

Classification such as:

```text
Code
HighEntropy
CryptoKey
AI
```

should be interpreted as triage metadata rather than definitive identification.

Dictionary and especially fuzzy matching can become expensive with very large wordlists.

The `--raw` mode aims to provide fast conventional string extraction, but `strx` does **not currently claim full command-line compatibility with GNU `strings`**.

---

## Roadmap

Potential future work includes:

```text
streaming extraction for very large stdin sources
parallel heuristic processing
SIMD-assisted scanning
Base64URL decoding
UTF-32 extraction
PE / ELF / Mach-O section awareness
YARA-compatible output integration
structured IoC export
entropy visualization
recursive decoding with bounded depth
plugin-based heuristics
benchmark suite
additional forensic output formats
```

Features should only be added when they preserve predictable resource usage and the original evidence model.

---

## Security

If you discover a security issue in `strx`, please avoid publishing exploit details before the issue can be investigated.

See [`SECURITY.md`](SECURITY.md) for reporting information.

---

## License

`strx` is licensed under the MIT License.

See [`LICENSE`](LICENSE) for details.
