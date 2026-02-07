#!/usr/bin/env python3
"""
Build a reviewer profile from your own published papers.

Usage:
    python3 build_profile.py topics.txt ~/papers/*.pdf
    python3 build_profile.py topics.txt ./my-papers/

Outputs: reviewer_profile.json (topic scores + keyword scores)
Import this file into the Bidding Helper web app.

Dependencies:
    pip install pymupdf   (or: pip install PyMuPDF)
"""

import sys
import os
import re
import json
import math
from pathlib import Path
from collections import Counter

try:
    import fitz  # PyMuPDF
except ImportError:
    print("ERROR: PyMuPDF is required. Install with: pip install pymupdf")
    sys.exit(1)


# ── Same stemmer as the web app ──
def simple_stem(word):
    if len(word) < 4:
        return word
    if word.endswith('ies') and len(word) > 4:
        return word[:-3] + 'y'
    if len(word) > 5 and any(word.endswith(s) for s in ('ches', 'shes', 'ses', 'xes', 'zes')):
        return word[:-2]
    if (word.endswith('s') and not word.endswith(('ss', 'us', 'is', 'ous'))
            and len(word) > 4):
        return word[:-1]
    if word.endswith('ied') and len(word) > 4:
        return word[:-3] + 'y'
    if word.endswith('ed') and not word.endswith('eed') and len(word) > 5:
        base = word[:-2]
        if len(base) >= 3 and base[-1] == base[-2]:
            return base[:-1]
        return base
    if word.endswith('ing') and len(word) > 5:
        base = word[:-3]
        if len(base) < 3:
            return word
        if base[-1] == base[-2]:
            return base[:-1]
        return base
    if (word.endswith('tion') or word.endswith('sion')) and len(word) > 6:
        return word[:-3]
    return word


# ── Same stop words as the web app ──
STOP_WORDS = {
    'the','a','an','and','or','but','in','on','at','to','for','of','with','by','from','as','is',
    'was','are','were','be','been','being','have','has','had','do','does','did','will','would',
    'could','should','may','might','shall','can','this','that','these','those','it','its','we',
    'our','they','their','them','he','she','his','her','not','no','nor','so','if','then','than',
    'too','very','just','about','above','after','again','all','also','am','any','because','before',
    'between','both','during','each','few','further','get','got','here','how','into','more','most',
    'much','my','myself','only','other','out','own','same','some','such','there','through','under',
    'until','up','what','when','where','which','while','who','whom','why','you','your',
    'paper','approach','system','systems','propose','proposed','present','presented','presents',
    'show','shows','shown','demonstrate','demonstrates','novel','new','based','using','use','used',
    'uses','results','result','method','methods','framework','technique','techniques','work',
    'study','first','also','however','existing','previous','prior','provide','provides',
    'evaluate','evaluation','analysis','performance','significant','significantly','achieve',
    'achieves','improvement','real','world','practical','effective','effectively','implementation',
    'implement','implements','prototype','overhead','design','designed','develop','developed',
    'different','problem','problems','solution','solutions','address','addresses','consider',
    'considers','introduce','introduces','investigate','investigates','focus','large','number',
    'well','known','make','makes','one','two','three','many','several','various','without',
    'over','across','among','within','since','allow','allows','enable','enables','require',
    'requires','often','thus','therefore','moreover','furthermore','addition','additionally',
    'particular','especially','specifically','general','commonly','typically',
    'respectively','given','including','include','includes','need','needs','due','case','cases',
    'example','examples','way','ways','data','information','process','order','set','high','low',
    'security','secure','attack','attacks','attacker','attackers','vulnerability','vulnerabilities',
    'threat','threats','defense','defenses','protection','protect','protects','malicious',
    'non','pre','per','via','sub','multi','semi','anti','inter','intra','cross','based',
    'able','end','run','yet','let','whether','while','upon','whose','been','being',
    'into','such','then','than','them','their','these','those','most','other','some',
}


def tokenize(text):
    words = re.sub(r'[^a-z0-9]', ' ', text.lower()).split()
    return [w for w in words if len(w) >= 3 and w not in STOP_WORDS]


def extract_pdf_text(path):
    try:
        doc = fitz.open(path)
        text = []
        for page in doc:
            text.append(page.get_text())
        doc.close()
        return '\n'.join(text)
    except Exception as e:
        print(f"  WARNING: Could not read {path}: {e}")
        return ''


def parse_topics_file(path):
    """Parse the topics file (indented tree, one topic per line).

    Format:
        Parent Topic
          Child Topic
          Another Child
        Another Parent
    """
    topics = []  # list of full topic strings like "Network security: Intrusion..."
    current_parent = None

    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue

            if line.startswith('  '):
                # Child topic (indented)
                child = line.strip()
                if current_parent and child:
                    topics.append(f"{current_parent}: {child}")
            else:
                # Parent topic (no indent)
                current_parent = line.strip()
                if current_parent:
                    topics.append(current_parent)

    return topics


# ── Enriched topic descriptions ──
# Hand-crafted keyword expansions for common security conference topics.
# These capture technical terms, tools, acronyms, and concepts that papers
# in each area typically use, beyond what the topic name alone conveys.
TOPIC_DESCRIPTIONS = {
    # ── Applications of cryptography ──
    "Applications of cryptography":
        "cryptography encryption decryption key management PKI certificates "
        "digital signatures public key private key symmetric asymmetric cipher "
        "key exchange authenticated encryption",

    "Applications of cryptography: Analysis of deployed cryptography and cryptographic protocols":
        "TLS SSL HTTPS SSH DTLS QUIC certificate transparency X.509 PKI "
        "key exchange Diffie-Hellman RSA ECDSA ECDH protocol analysis handshake "
        "cipher suite downgrade negotiation certificate pinning HSTS OCSP "
        "Let's Encrypt ACME record layer session resumption",

    "Applications of cryptography: Blockchains and distributed ledger security":
        "blockchain bitcoin ethereum smart contract Solidity consensus mining "
        "cryptocurrency DeFi decentralized finance merkle tree proof of work "
        "proof of stake token NFT validator mempool MEV front-running flash loan "
        "reentrancy bridge cross-chain oracle",

    "Applications of cryptography: Cryptographic implementation analysis":
        "side-channel timing constant-time implementation bug cryptographic library "
        "OpenSSL BoringSSL random number generator entropy PRNG RNG leakage "
        "fault injection padding oracle Bleichenbacher power analysis glitch",

    "Applications of cryptography: New cryptographic protocols with real-world applications":
        "zero-knowledge proof ZKP zk-SNARK zk-STARK MPC secure multi-party computation "
        "homomorphic encryption FHE oblivious RAM ORAM secret sharing garbled circuit "
        "private set intersection PSI oblivious transfer threshold cryptography "
        "verifiable computation functional encryption attribute-based encryption "
        "proxy re-encryption searchable encryption",

    # ── Hardware security ──
    "Hardware security":
        "hardware chip processor CPU GPU FPGA ASIC silicon IC integrated circuit "
        "microarchitecture transistor gate SoC",

    "Hardware security: Automated security analysis of hardware designs and implementation":
        "HDL Verilog VHDL SystemVerilog RTL hardware verification formal verification "
        "information flow gate-level netlist synthesis hardware design EDA "
        "property checking model checking assertion",

    "Hardware security: Cyber-physical systems security":
        "SCADA ICS industrial control system PLC programmable logic controller "
        "automotive CAN bus ECU OBD vehicle V2X power grid smart grid energy "
        "sensor actuator cyber-physical CPS process control safety-critical "
        "real-time control loop supervisory",

    "Hardware security: Embedded systems security":
        "firmware microcontroller ARM Cortex RTOS bootloader secure boot embedded "
        "IoT device peripheral JTAG debug interface flash memory OTA update "
        "bare-metal interrupt handler watchdog MCU SoC trusted boot chain",

    "Hardware security: Methods for detection of malicious or counterfeit hardware":
        "hardware trojan counterfeit supply chain chip IC verification testing "
        "PUF physically unclonable function fingerprint authentication golden model "
        "side-channel detection ring oscillator aging degradation",

    "Hardware security: Secure computer architectures":
        "TEE trusted execution environment SGX TrustZone enclave isolation "
        "memory protection RISC-V capability tagged architecture memory tagging "
        "MTE ARM CCA confidential computing SEV TDX keystone sanctum "
        "compartmentalization privilege separation hardware security module HSM",

    "Hardware security: Side channels":
        "cache timing power analysis electromagnetic Spectre Meltdown "
        "microarchitectural speculative execution covert channel Rowhammer "
        "Flush+Reload Prime+Probe cache line TLB branch predictor "
        "transient execution prefetch LLC last-level cache DRAM row buffer "
        "frequency throttling DVFS thermal magnetic",

    # ── Human Aspects ──
    "Human Aspects":
        "human user people perception behavior decision mental model attitude "
        "comprehension cognition sociotechnical",

    "Human Aspects: Security and privacy law, policy and/or ethics":
        "GDPR regulation compliance policy legal ethics consent data protection "
        "surveillance law CCPA HIPAA FERPA COPPA right to be forgotten "
        "data breach notification jurisdiction cross-border transfer DPA "
        "impact assessment proportionality accountability transparency",

    "Human Aspects: Security education and training":
        "CTF capture the flag training education curriculum awareness "
        "phishing simulation security culture pedagogy gamification "
        "cybersecurity workforce skill gap exercise tabletop competition "
        "learning outcome assessment certification",

    "Human Aspects: Understanding, measuring, quantifying, and protecting users from: information manipulation, mis/disinformation, harassment, extremism, and abuse via qualitative and quantitative methods":
        "misinformation disinformation fake news social media manipulation bot "
        "harassment extremism content moderation hate speech propaganda "
        "influence operation troll farm deepfake synthetic media fact-check "
        "platform abuse coordinated inauthentic behavior radicalization "
        "online safety trust narrative framing echo chamber",

    "Human Aspects: Usable security and privacy":
        "usability user study mental model authentication UX password warning "
        "indicator permission consent dialog notification interface design "
        "human-computer interaction HCI survey interview think-aloud "
        "Likert SUS task completion error rate adoption acceptance "
        "two-factor 2FA FIDO passkey biometric",

    # ── Network security ──
    "Network security":
        "network protocol packet traffic TCP UDP IP router switch firewall "
        "proxy gateway middlebox latency bandwidth throughput",

    "Network security: Analysis of network and security protocols":
        "TLS DNS BGP DNSSEC RPKI IPsec WireGuard VPN protocol analysis "
        "formal verification network protocol QUIC DoH DoT HTTPS certificate "
        "handshake key exchange cipher suite OSPF IS-IS MPLS segment routing "
        "SRv6 NTP Kerberos RADIUS LDAP",

    "Network security: Denial-of-service attacks and countermeasures":
        "DDoS denial of service amplification reflection flooding botnet "
        "rate limiting CDN mitigation SYN flood volumetric application layer "
        "carpet bombing memcached NTP DNS amplification scrubbing center "
        "blackhole sinkhole anycast load balancing",

    "Network security: Intrusion and anomaly detection and prevention":
        "IDS IPS intrusion detection anomaly network monitoring NIDS "
        "signature behavioral analysis traffic classification deep packet "
        "inspection alert SIEM rule log correlation threat intelligence "
        "honeypot deception indicator of compromise IOC endpoint detection EDR "
        "NetFlow IPFIX machine learning for detection",

    "Network security: Network infrastructure security":
        "BGP hijacking DNS routing autonomous system AS CDN middlebox "
        "firewall NAT SDN software-defined networking NFV peering IX "
        "internet exchange point prefix origin validation ROA route leak "
        "MANRS domain registrar WHOIS",

    "Network security: Wireless security":
        "WiFi Bluetooth 5G LTE cellular radio spectrum jamming WPA 802.11 "
        "BLE beacon NFC RFID Zigbee Z-Wave LoRa LPWAN mesh baseband "
        "SIM eSIM IMSI catcher stingray AKA handover roaming",

    # ── Privacy and Anonymity ──
    "Privacy and Anonymity":
        "privacy anonymity private anonymous confidential personal data "
        "tracking surveillance profiling inference",

    "Privacy and Anonymity: Anonymity":
        "Tor onion routing anonymous communication mix network mixnet "
        "metadata traffic analysis censorship circumvention relay bridge "
        "hidden service onion service Riffle Vuvuzela Loopix PIR "
        "private information retrieval unlinkability pseudonym",

    "Privacy and Anonymity: Privacy attacks":
        "fingerprinting browser fingerprint device fingerprint tracking "
        "re-identification de-anonymization inference linkage correlation "
        "website fingerprinting traffic analysis canvas font WebGL "
        "cookie syncing cross-site tracking supercookie bounce tracking "
        "location tracking app tracking",

    "Privacy and Anonymity: Privacy metrics":
        "differential privacy epsilon delta privacy loss budget composition "
        "information leakage mutual information entropy k-anonymity "
        "l-diversity t-closeness Renyi divergence privacy accounting "
        "quantification measurement indistinguishability",

    "Privacy and Anonymity: Privacy-preserving computation":
        "MPC secure multi-party computation homomorphic encryption FHE "
        "secret sharing garbled circuit oblivious transfer oblivious RAM "
        "TEE for privacy federated learning secure aggregation "
        "private set intersection PSI private information retrieval PIR "
        "trusted execution differential privacy mechanism",

    "Privacy and Anonymity: Surveillance and censorship":
        "censorship Great Firewall GFW VPN blocking deep packet inspection "
        "surveillance interception wiretap lawful intercept mass surveillance "
        "Tor blocking circumvention tool Pluggable Transport domain fronting "
        "SNI blocking ESNI ECH throttling internet shutdown",

    # ── Privacy of ML ──
    "Privacy of ML":
        "machine learning privacy federated learning differential privacy "
        "membership inference model inversion gradient leakage training data "
        "extraction memorization unlearning data poisoning label privacy "
        "privacy-preserving machine learning PATE knowledge distillation "
        "DP-SGD clipping noise mechanism Gaussian Laplace",

    # ── Security and Privacy for Web, Mobile, and Emerging Technologies ──
    "Security and Privacy for Web, Mobile, and Emerging Technologies":
        "web mobile browser app emerging technology platform ecosystem "
        "third-party SDK library API",

    "Security and Privacy for Web, Mobile, and Emerging Technologies: Games":
        "game security cheating anti-cheat game engine multiplayer online "
        "virtual economy exploit bot aiming wallhack integrity",

    "Security and Privacy for Web, Mobile, and Emerging Technologies: IoT":
        "IoT Internet of Things smart home connected device hub Zigbee Z-Wave "
        "MQTT CoAP smart speaker voice assistant wearable thermostat camera "
        "doorbell fitness tracker home automation companion app cloud backend",

    "Security and Privacy for Web, Mobile, and Emerging Technologies: Mobile":
        "Android iOS mobile app permission SDK third-party library mobile malware "
        "APK app store Google Play sideload intent broadcast receiver "
        "accessibility service overlay notification TikTok WhatsApp Telegram "
        "in-app browser WebView deep link",

    "Security and Privacy for Web, Mobile, and Emerging Technologies: VR/AR":
        "virtual reality VR augmented reality AR XR mixed reality immersive "
        "head-mounted display HMD spatial computing eye tracking hand tracking "
        "avatar metaverse haptic controller headset Oculus Quest",

    "Security and Privacy for Web, Mobile, and Emerging Technologies: Web":
        "browser JavaScript XSS cross-site scripting CSRF CSP content security policy "
        "cookie web application OAuth SSO single sign-on extension WebAssembly Wasm "
        "DOM iframe postMessage CORS origin SOP same-origin policy service worker "
        "supply chain npm CDN subresource integrity SRI",

    # ── Security of ML ──
    "Security of ML":
        "adversarial example adversarial robustness evasion attack perturbation "
        "poisoning backdoor trojan neural network deep learning model stealing "
        "model extraction watermark certified defense verification "
        "LLM large language model prompt injection jailbreak alignment "
        "ChatGPT GPT foundation model generative AI safety guardrails "
        "classifier gradient FGSM PGD C&W AutoAttack",

    # ── Software security ──
    "Software security":
        "software binary executable code vulnerability exploit patch bug "
        "compiler linker loader runtime",

    "Software security: Automated security analysis of source code and binaries":
        "static analysis binary analysis symbolic execution taint analysis "
        "dataflow control flow graph CFG decompilation reverse engineering "
        "abstract interpretation type inference code similarity clone detection "
        "LLVM IR intermediate representation lifting disassembly Ghidra IDA "
        "angr BAP KLEE S2E Manticore CodeQL Semgrep",

    "Software security: Forensics and diagnostics for security":
        "forensics incident response log analysis attribution root cause "
        "debugging provenance audit trail memory forensics disk forensics "
        "network forensics timeline reconstruction artifact evidence "
        "chain of custody volatile memory crash dump core dump triage",

    "Software security: Fuzzing and vulnerability discovery":
        "fuzzing fuzz AFL libFuzzer honggfuzz coverage-guided mutation seed "
        "corpus crash bug finding grammar-based directed fuzzing concolic "
        "hybrid fuzzing sanitizer ASAN MSAN UBSAN harness driver "
        "generator emulation QEMU snapshot state",

    "Software security: Malware analysis":
        "malware ransomware botnet C2 command and control packer obfuscation "
        "sandbox dynamic analysis behavioral analysis classification detection "
        "evasion anti-analysis polymorphic metamorphic dropper downloader "
        "payload shellcode implant RAT rootkit worm spyware",

    "Software security: Program analysis":
        "control flow integrity CFI memory safety type safety sanitizer "
        "bounds checking use-after-free buffer overflow heap stack ROP "
        "return-oriented programming JOP exploitation mitigation ASLR DEP "
        "stack canary shadow stack pointer authentication PAC "
        "spatial temporal memory corruption dangling pointer double free "
        "integer overflow format string gadget exploit chain",

    # ── System security ──
    "System security":
        "operating system kernel driver process thread system call "
        "privilege isolation sandbox container virtual machine",

    "System security: Cloud computing security":
        "cloud container Docker Kubernetes VM hypervisor serverless "
        "multi-tenant isolation microservice AWS Azure GCP Lambda function "
        "Fargate ECS EKS pod namespace secret configuration IAM role "
        "access control API gateway edge computing CDN",

    "System security: Distributed systems security":
        "consensus Byzantine fault tolerance BFT replication distributed trust "
        "peer-to-peer P2P coordination Raft Paxos PBFT state machine "
        "replication quorum availability partition tolerance CAP "
        "decentralized federated gossip protocol membership overlay",

    "System security: Operating systems security":
        "kernel Linux Windows macOS privilege escalation sandbox namespace "
        "seccomp SELinux AppArmor driver system call syscall eBPF "
        "module capability cgroup procfs sysfs ptrace KASLR SMEP SMAP "
        "page table permission bit root setuid",
}


def score_topics(topics, corpus_text):
    """Score each topic by keyword overlap with the corpus.

    Uses both the topic name and the enriched description for matching.
    """
    text_lower = corpus_text.lower()
    scores = {}

    for topic in topics:
        # Combine topic name with enriched description (if available)
        description = TOPIC_DESCRIPTIONS.get(topic, '')
        match_text = topic.replace(':', ' ') + ' ' + description
        topic_words = tokenize(match_text)

        if not topic_words:
            scores[topic] = 0
            continue

        # Count how many times topic words appear in the corpus
        match_count = 0
        for tw in topic_words:
            match_count += len(re.findall(r'\b' + re.escape(tw) + r'\w*\b', text_lower))

        # Normalize by number of topic words
        scores[topic] = match_count / len(topic_words)

    return scores


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 build_profile.py <topics-file> <pdf-file-or-dir> [pdf-file-or-dir ...]")
        print("\nExample:")
        print("  python3 build_profile.py topics.txt ~/papers/")
        print("  python3 build_profile.py topics.txt paper1.pdf paper2.pdf")
        sys.exit(1)

    topics_file = sys.argv[1]
    pdf_args = sys.argv[2:]

    # Collect PDF files
    pdf_files = []
    for arg in pdf_args:
        p = Path(arg)
        if p.is_dir():
            pdf_files.extend(sorted(p.glob('*.pdf')))
        elif p.is_file() and p.suffix.lower() == '.pdf':
            pdf_files.append(p)
        else:
            print(f"WARNING: Skipping {arg} (not a PDF or directory)")

    if not pdf_files:
        print("ERROR: No PDF files found.")
        sys.exit(1)

    # Parse topics
    topics = parse_topics_file(topics_file)
    if not topics:
        print(f"ERROR: No topics parsed from {topics_file}")
        sys.exit(1)
    print(f"Parsed {len(topics)} topics from {topics_file}")

    # Extract text from all PDFs
    print(f"Processing {len(pdf_files)} PDF files...")
    all_text = []
    for pdf in pdf_files:
        print(f"  Reading {pdf.name}...")
        text = extract_pdf_text(str(pdf))
        if text:
            all_text.append(text)

    corpus = '\n\n'.join(all_text)
    print(f"Extracted {len(corpus):,} characters from {len(all_text)} files.")

    if not corpus.strip():
        print("ERROR: No text extracted from PDFs.")
        sys.exit(1)

    # ── Score topics ──
    raw_topic_scores = score_topics(topics, corpus)

    # Normalize to 0-10 scale
    max_ts = max(raw_topic_scores.values()) if raw_topic_scores else 1
    if max_ts == 0:
        max_ts = 1
    topic_scores = {}
    for topic, raw in raw_topic_scores.items():
        normalized = round((raw / max_ts) * 10)
        if normalized > 0:
            topic_scores[topic] = normalized

    # ── Extract keywords with TF-IDF ──
    # Treat each PDF as a document for TF-IDF, compute against the corpus
    doc_tokens = []
    df = Counter()
    for text in all_text:
        words = tokenize(text)
        stems = [simple_stem(w) for w in words]
        doc_tokens.append(stems)
        for s in set(stems):
            df[s] += 1

    N = len(all_text)
    # Also compute term frequency across the entire corpus
    corpus_stems = []
    stem_to_forms = {}
    for text in all_text:
        words = tokenize(text)
        for w in words:
            s = simple_stem(w)
            corpus_stems.append(s)
            if s not in stem_to_forms:
                stem_to_forms[s] = Counter()
            stem_to_forms[s][w] += 1

    corpus_tf = Counter(corpus_stems)
    total_stems = len(corpus_stems) or 1

    # Compute TF-IDF-like score for each stem
    # TF = count in corpus / total stems
    # IDF = log(N / df) but with N being small (number of papers), so we use a simpler boost:
    #   stems appearing in MORE of the user's papers are more representative
    keyword_scores_raw = {}
    for stem, count in corpus_tf.items():
        if df[stem] < 1:
            continue
        # Coverage: fraction of user's papers containing this stem (higher = more representative)
        coverage = df[stem] / N
        # Frequency: how often it appears overall
        freq = count / total_stems
        # Combined score: favor terms that appear frequently AND across many papers
        keyword_scores_raw[stem] = freq * (0.5 + coverage) * 1000

    # Get top keywords, pick the most common surface form for display
    sorted_kw = sorted(keyword_scores_raw.items(), key=lambda x: -x[1])

    # Normalize top keywords to 1-10 scale
    max_kw = sorted_kw[0][1] if sorted_kw else 1
    keyword_scores = {}
    for stem, raw in sorted_kw[:500]:
        normalized = round((raw / max_kw) * 10)
        if normalized > 0:
            # Use the most common surface form as the key (for readability)
            # but also include the stem for matching
            best_form = stem_to_forms[stem].most_common(1)[0][0]
            keyword_scores[stem] = {
                'score': normalized,
                'display': best_form,
            }

    # ── Build profile ──
    profile = {
        'description': f'Profile built from {len(all_text)} papers: {", ".join(p.stem for p in pdf_files[:5])}{"..." if len(pdf_files) > 5 else ""}',
        'topicScores': topic_scores,
        'keywordScores': {stem: info['score'] for stem, info in keyword_scores.items()},
        'keywordDisplay': {stem: info['display'] for stem, info in keyword_scores.items()},
    }

    outfile = os.path.join(os.path.dirname(topics_file) or '.', 'reviewer_profile.json')
    with open(outfile, 'w', encoding='utf-8') as f:
        json.dump(profile, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Profile written to {outfile}")
    print(f"\nTop topic scores:")
    for topic, score in sorted(topic_scores.items(), key=lambda x: -x[1])[:10]:
        print(f"  {score:2d}  {topic}")
    print(f"\nTop keyword scores:")
    for stem, info in list(keyword_scores.items())[:15]:
        print(f"  {info['score']:2d}  {info['display']} (stem: {stem})")
    print(f"\nImport this file in the Bidding Helper web app.")


if __name__ == '__main__':
    main()
