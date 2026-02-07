#!/usr/bin/env python3
"""Generate a realistic test CSV for the bidding helper.
Run: python3 generate_test_data.py
Output: test_revprefs.csv (~200 papers)
"""
import csv, random, os

# Realistic security conference topic tree
TOPIC_TREE = {
    "Applications of cryptography": [
        "Analysis of deployed cryptography and cryptographic protocols",
        "Cryptographic implementation analysis",
        "New cryptographic protocols with real-world applications",
    ],
    "Network security": [
        "Analysis of network and security protocols",
        "Denial-of-service attacks and defenses",
        "Network intrusion detection and prevention",
        "Network traffic analysis",
    ],
    "Systems security": [
        "Operating system security",
        "Browser security",
        "Firmware and embedded device security",
        "Mobile system security",
        "Cloud and virtualization security",
    ],
    "Software security": [
        "Vulnerability detection and analysis",
        "Exploit techniques and mitigations",
        "Fuzzing and testing",
        "Program analysis",
        "Memory safety",
    ],
    "Web security": [
        "Web application security",
        "Authentication and access control",
        "Cross-site scripting and injection attacks",
        "Content security policies",
    ],
    "Privacy": [
        "Differential privacy",
        "Anonymous communication",
        "Data anonymization and de-anonymization",
        "Location privacy",
        "Surveillance and censorship",
    ],
    "Machine learning and security": [
        "Adversarial machine learning",
        "ML-based security analysis",
        "Privacy in machine learning",
        "LLM security",
    ],
    "Hardware security": [
        "Side-channel attacks and defenses",
        "Trusted execution environments",
        "Hardware trojans",
        "Physical security",
    ],
    "Usable security and privacy": [
        "Authentication usability",
        "Security warnings and indicators",
        "User studies",
        "Developer security practices",
    ],
    "Measurement studies": [
        "Internet measurement",
        "Malware measurement",
        "Ecosystem measurement",
        "Security of IoT devices",
    ],
    "Blockchain and distributed systems": [
        "Smart contract security",
        "Consensus protocol security",
        "Decentralized finance security",
    ],
    "Forensics and abuse": [
        "Digital forensics",
        "Spam and abuse detection",
        "Underground economy",
        "Phishing",
    ],
}

ALL_TOPICS = []
for parent, children in TOPIC_TREE.items():
    ALL_TOPICS.append(parent)
    for child in children:
        ALL_TOPICS.append(f"{parent}: {child}")

# Word pools for generating titles and abstracts
TITLE_PATTERNS = [
    "{adj} {noun} for {area}",
    "Towards {adj} {noun} in {area}",
    "A {adj} Approach to {noun} in {area}",
    "{verb}ing {noun}: A {adj} Framework for {area}",
    "On the {noun} of {adj} {area} Systems",
    "{noun}Guard: {adj} {area} {noun2} Detection",
    "Breaking and Fixing {adj} {noun} in {area}",
    "Rethinking {noun} for {adj} {area}",
    "{adj} {noun} Against {threat} in {area}",
    "An Empirical Study of {noun} in {area}",
    "{verb}ing {threat}: {adj} {noun} for {area}",
    "Practical {adj} {noun} for {area} Applications",
    "SoK: {adj} {noun} in {area}",
    "{noun}Scope: Automated {noun2} Analysis for {area}",
    "Understanding {threat} in {adj} {area} Systems",
]

ADJS = [
    "Secure", "Efficient", "Scalable", "Privacy-Preserving", "Robust",
    "Automated", "Lightweight", "Practical", "Formal", "Dynamic",
    "Transparent", "Resilient", "Adaptive", "Verifiable", "Trustworthy",
    "Decentralized", "Real-Time", "Context-Aware", "Zero-Knowledge",
    "Federated", "Post-Quantum", "Differential", "Proactive",
]

NOUNS = [
    "Authentication", "Encryption", "Vulnerability", "Protocol",
    "Framework", "Defense", "Analysis", "Detection", "Verification",
    "Inference", "Attestation", "Isolation", "Fuzzing", "Monitoring",
    "Fingerprinting", "Sanitization", "Obfuscation", "Patching",
    "Provenance", "Computation", "Delegation", "Revocation",
]

NOUNS2 = [
    "Malware", "Intrusion", "Anomaly", "Exploit", "Vulnerability",
    "Threat", "Leakage", "Tampering", "Injection", "Evasion",
]

AREAS = [
    "IoT Networks", "Cloud Computing", "Mobile Devices", "Web Applications",
    "Smart Contracts", "Machine Learning Models", "Autonomous Vehicles",
    "Industrial Control Systems", "5G Networks", "Edge Computing",
    "Federated Learning", "Large Language Models", "DNS Infrastructure",
    "TLS Deployments", "Container Orchestration", "Supply Chains",
    "Social Networks", "Messaging Systems", "Browser Extensions",
    "Embedded Systems", "Kernel Space", "SGX Enclaves",
]

THREATS = [
    "Adversarial Attacks", "Side-Channel Leakage", "Data Poisoning",
    "Man-in-the-Middle Attacks", "Privilege Escalation", "Information Leakage",
    "Denial of Service", "Code Injection", "Firmware Tampering",
    "Model Extraction", "Membership Inference", "Replay Attacks",
]

VERBS = ["Detect", "Mitigat", "Analyz", "Fuzz", "Monitor", "Secur", "Protect", "Verif"]

ABSTRACT_SENTENCES = [
    "We present a novel approach to {topic} that achieves significant improvements over prior work.",
    "Our system leverages {technique} to provide strong security guarantees while maintaining high performance.",
    "We evaluate our approach on {num} real-world datasets and demonstrate {metric}% improvement.",
    "The key insight is that {technique} can be combined with {technique2} to overcome the limitations of existing solutions.",
    "We identify {num} previously unknown vulnerabilities in widely deployed {system} implementations.",
    "Our analysis reveals that {percent}% of {system} deployments are vulnerable to {attack}.",
    "We propose a defense mechanism based on {technique} that incurs only {overhead}% overhead.",
    "Through extensive experimentation, we show that our method outperforms state-of-the-art baselines.",
    "We conduct the first large-scale measurement study of {topic} across {num} organizations.",
    "Our formal analysis proves that the proposed protocol satisfies {property} under the {model} model.",
    "The results demonstrate that {technique} is both practical and effective against sophisticated adversaries.",
    "We implement and evaluate a prototype system that processes {num} requests per second.",
    "Our user study with {num} participants confirms that the system is both secure and usable.",
    "We discover fundamental limitations in current {topic} approaches and propose practical alternatives.",
    "The system has been deployed in production and protects over {num} users.",
    "We introduce a new threat model that captures realistic {attack} scenarios.",
    "Our framework enables developers to write secure code with minimal additional effort.",
    "We open-source our tools and datasets to facilitate future research in this area.",
]

TECHNIQUES = [
    "static analysis", "dynamic taint tracking", "symbolic execution",
    "differential privacy", "homomorphic encryption", "secure multi-party computation",
    "trusted execution environments", "program synthesis", "abstract interpretation",
    "deep learning", "reinforcement learning", "graph neural networks",
    "formal verification", "type systems", "information flow control",
    "binary analysis", "control-flow integrity", "memory tagging",
    "zero-knowledge proofs", "oblivious RAM", "garbled circuits",
]

SYSTEMS = [
    "TLS", "SSH", "DNS", "BGP", "OAuth", "HTTPS", "VPN", "Bluetooth",
    "WiFi", "NFC", "USB", "Kubernetes", "Docker", "Android", "iOS",
    "Chrome", "Firefox", "OpenSSL", "WireGuard", "Signal",
]

ATTACKS = [
    "cache timing attacks", "rowhammer attacks", "speculative execution attacks",
    "return-oriented programming", "SQL injection", "cross-site scripting",
    "DNS rebinding", "ARP spoofing", "BGP hijacking", "phishing attacks",
]

PROPERTIES = [
    "confidentiality", "integrity", "availability", "forward secrecy",
    "non-repudiation", "anonymity", "unlinkability", "plausible deniability",
]

def gen_title():
    pat = random.choice(TITLE_PATTERNS)
    return pat.format(
        adj=random.choice(ADJS),
        noun=random.choice(NOUNS),
        noun2=random.choice(NOUNS2),
        area=random.choice(AREAS),
        threat=random.choice(THREATS),
        verb=random.choice(VERBS),
    )

def gen_abstract():
    n_paragraphs = random.randint(1, 3)
    paragraphs = []
    for _ in range(n_paragraphs):
        n_sentences = random.randint(3, 7)
        sentences = []
        for _ in range(n_sentences):
            s = random.choice(ABSTRACT_SENTENCES).format(
                topic=random.choice(NOUNS).lower(),
                technique=random.choice(TECHNIQUES),
                technique2=random.choice(TECHNIQUES),
                num=random.choice([5, 10, 15, 23, 47, 100, 250, 500, 1000, 10000, 50000]),
                metric=random.randint(10, 95),
                percent=random.randint(15, 85),
                system=random.choice(SYSTEMS),
                attack=random.choice(ATTACKS),
                overhead=random.choice([0.5, 1.2, 2.3, 3.7, 5, 8, 12]),
                property=random.choice(PROPERTIES),
                model=random.choice(["Dolev-Yao", "UC", "ROM", "standard", "CRS"]),
            )
            sentences.append(s)
        paragraphs.append(" ".join(sentences))
    return "\n\n".join(paragraphs)

def gen_topics():
    # Pick 1-4 parent topics, then for each pick 0-3 children
    n_parents = random.randint(1, 4)
    parents = random.sample(list(TOPIC_TREE.keys()), n_parents)
    topics = []
    for p in parents:
        topics.append(p)
        children = TOPIC_TREE[p]
        if children:
            n_children = random.randint(0, min(3, len(children)))
            for c in random.sample(children, n_children):
                topics.append(f"{p}: {c}")
    return "; ".join(topics)

def main():
    outfile = os.path.join(os.path.dirname(__file__) or '.', 'test_revprefs.csv')
    n_papers = 200

    used_ids = set()
    with open(outfile, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['paper', 'title', 'preference', 'abstract', 'topics'])

        for _ in range(n_papers):
            while True:
                pid = random.randint(1000, 2999)
                if pid not in used_ids:
                    used_ids.add(pid)
                    break
            title = gen_title()
            pref = random.choice([0] * 15 + [-100, -100] + [20, 10, -20])
            abstract = gen_abstract()
            topics = gen_topics()
            writer.writerow([pid, title, pref, abstract, topics])

    print(f"Generated {n_papers} test papers in {outfile}")

if __name__ == '__main__':
    main()
