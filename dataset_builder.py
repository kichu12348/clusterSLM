import json
import random

SYSTEM_PROMPT = """You are a security auditor SLM. Analyze the scoped code and partition boundaries.
First, use a  block to trace the data flow from the incoming boundary to any potential sinks. 
Then, output a valid JSON list with findings, or an empty list [] if the code is safe. Return ONLY valid JSON."""

# 10 Core Templates (5 Vulnerable, 5 Safe)
BASE_PATTERNS = [
    {
        "type": "SQLi_Vuln",
        "code": "def get_user_data_{i}(user_id):\n    query = f'SELECT * FROM data WHERE id = {user_id}'\n    return db.execute(query)",
        "edge": "api.routes.get_data -> db.repository.get_user_data_{i}",
        "vuln": True,
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "thought": "The function receives `user_id` from the API boundary. It interpolates this directly into a raw SQL string `query` without parameterization. This is passed to `db.execute`. This is an exploitable SQL Injection sink.",
        "evidence": "Raw SQL string formatting with untrusted input.",
    },
    {
        "type": "SQLi_Safe",
        "code": "def get_user_data_{i}(user_id):\n    query = 'SELECT * FROM data WHERE id = ?'\n    return db.execute(query, (user_id,))",
        "edge": "api.routes.get_data -> db.repository.get_user_data_{i}",
        "vuln": False,
        "thought": "The function receives `user_id` from the API. However, it uses parameterized queries (`?`) to pass the input safely to the database driver. The input is structurally isolated from the SQL command. No vulnerability.",
    },
    {
        "type": "Cmd_Vuln",
        "code": "def ping_host_{i}(host):\n    import subprocess\n    subprocess.run('ping -c 4 ' + host, shell=True)",
        "edge": "admin.diagnostics -> network.ping_host_{i}",
        "vuln": True,
        "cwe": "CWE-78",
        "name": "Command Injection",
        "thought": "The function receives `host` from the admin boundary. It concatenates this unvalidated string directly into a subprocess command executed with `shell=True`. An attacker can append shell operators (e.g., `;`). This is a Command Injection sink.",
        "evidence": "subprocess.run called with shell=True and concatenated untrusted input.",
    },
    {
        "type": "Cmd_Safe",
        "code": "def ping_host_{i}(host):\n    import subprocess\n    subprocess.run(['ping', '-c', '4', host], shell=False)",
        "edge": "admin.diagnostics -> network.ping_host_{i}",
        "vuln": False,
        "thought": "The function receives `host` from the boundary. It passes the command and arguments as a strict list to `subprocess.run` with `shell=False`. This prevents the OS from evaluating shell operators. No vulnerability.",
    },
    {
        "type": "Path_Vuln",
        "code": "def read_file_{i}(filename):\n    import os\n    path = os.path.join('/var/data', filename)\n    return open(path, 'r').read()",
        "edge": "docs.controller.download -> fs.read_file_{i}",
        "vuln": True,
        "cwe": "CWE-22",
        "name": "Path Traversal",
        "thought": "The function receives `filename` and joins it with a base directory. However, it does not normalize or validate the resulting path. An attacker can pass `../../etc/passwd` to escape the base directory. This is a Path Traversal sink.",
        "evidence": "os.path.join used without verifying the final path remains within the intended directory.",
    },
    {
        "type": "Path_Safe",
        "code": "def read_file_{i}(filename):\n    import os\n    base = '/var/data'\n    path = os.path.abspath(os.path.join(base, filename))\n    if not path.startswith(base):\n        raise ValueError('Invalid path')\n    return open(path, 'r').read()",
        "edge": "docs.controller.download -> fs.read_file_{i}",
        "vuln": False,
        "thought": "The function joins the `filename` but explicitly uses `os.path.abspath` and validates that the final path starts with the intended base directory. This neutralizes path traversal attempts. No vulnerability.",
    },
    {
        "type": "Deser_Vuln",
        "code": "def load_session_{i}(raw_bytes):\n    import pickle\n    return pickle.loads(raw_bytes)",
        "edge": "web.session.middleware -> cache.load_session_{i}",
        "vuln": True,
        "cwe": "CWE-502",
        "name": "Insecure Deserialization",
        "thought": "The function receives `raw_bytes` from an incoming session boundary and passes it straight into `pickle.loads`. Pickle deserialization executes arbitrary code embedded in the byte stream, so untrusted input reaching this sink lets an attacker achieve remote code execution. This is an Insecure Deserialization sink.",
        "evidence": "pickle.loads called directly on untrusted, unauthenticated input.",
    },
    {
        "type": "Deser_Safe",
        "code": "def load_session_{i}(raw_bytes):\n    import json\n    data = json.loads(raw_bytes)\n    return data",
        "edge": "web.session.middleware -> cache.load_session_{i}",
        "vuln": False,
        "thought": "The function receives `raw_bytes` from the boundary but deserializes it with `json.loads`, a data-only format with no facility for arbitrary code execution during parsing. No vulnerability.",
    },
    {
        "type": "Cred_Vuln",
        "code": "def connect_to_db_{i}():\n    conn = db.connect(host='prod-db', user='admin', password='Sup3rSecret_{i}!')\n    return conn",
        "edge": "app.startup -> db.client.connect_to_db_{i}",
        "vuln": True,
        "cwe": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "thought": "The function establishes a database connection using a plaintext password literal embedded directly in the source code. Anyone with read access to the repository or a compiled artifact can recover the credential, and rotating it requires a code change. This is a Hard-coded Credentials finding.",
        "evidence": "Plaintext password string literal passed directly to db.connect.",
    },
    {
        "type": "Cred_Safe",
        "code": "def connect_to_db_{i}():\n    import os\n    conn = db.connect(host='prod-db', user='admin', password=os.environ['DB_PASSWORD'])\n    return conn",
        "edge": "app.startup -> db.client.connect_to_db_{i}",
        "vuln": False,
        "thought": "The function reads the database password from an environment variable at runtime rather than embedding it in source code. The secret is not present in the codebase and can be rotated without a code change. No vulnerability.",
    },
]


def build_dataset():
    dataset = []
    # Loop 5 times to generate 50 examples total (10 patterns x 5)
    for i in range(1, 6):
        for pattern in BASE_PATTERNS:
            symbol = f"module_{i}.{pattern['type']}_{i}"

            payload = {
                "partition_id": random.randint(1, 10),
                "boundary_incoming": [
                    {"source": pattern["edge"].split(" -> ")[0], "target": symbol}
                ],
                "scoped_code": {symbol: pattern["code"].replace("{i}", str(i))},
            }

            if pattern["vuln"]:
                expected_json = json.dumps(
                    [
                        {
                            "vulnerability": pattern["name"],
                            "cwe": pattern["cwe"],
                            "function": symbol,
                            "confidence": 0.95,
                            "evidence": pattern["evidence"],
                        }
                    ],
                    indent=2,
                )
            else:
                expected_json = "[\n]"

            expected_output = (
                f"\n{pattern['thought']}\n\n\n```json\n{expected_json}\n```"
            )

            dataset.append(
                {
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(payload, indent=2)},
                        {"role": "assistant", "content": expected_output},
                    ]
                }
            )

    random.shuffle(dataset)

    # 80/20 Split (50 total -> 40 train / 10 test)
    train_data = dataset[:40]
    test_data = dataset[40:]

    with open("train.jsonl", "w") as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")
    with open("test.jsonl", "w") as f:
        for item in test_data:
            f.write(json.dumps(item) + "\n")

    print(f"[+] Generated train.jsonl (40 examples) and test.jsonl (10 examples)")


if __name__ == "__main__":
    build_dataset()
