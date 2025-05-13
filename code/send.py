import os
import json
import logging
from volcenginesdkarkruntime import Ark
from tqdm import tqdm  # 进度条工具
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# 初始化方舟客户端
api_key=os.environ.get("ARK_API_KEY")

# 待扫描根目录（相对于 send.py 的上两级目录）
BASE_DIR = os.path.join(os.path.dirname(__file__), "../data/pkg-Backstabber_300/npm")
# 输出文件（与 send.py 同目录）
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "scan_results.json")

# 支持的文本文件扩展名
TEXT_EXTS = {".txt", ".js", ".py", ".json", ".md", ".ts", ".jsx", ".tsx", ".ets"}
# 最大发送给模型的文件内容长度（字符数），超过则截断
MAX_CONTENT_LENGTH = 100000


def is_text_file(filename):
    return os.path.splitext(filename)[1].lower() in TEXT_EXTS


def extract_json(text):
    """
    从可能包含附加文本的响应中提取第一对大括号之间的 JSON。
    如果找不到匹配，则返回原始文本。
    """
    match = re.search(r"\{[\s\S]*\}", text)
    return match.group(0) if match else text


def scan_path(path_to_scan):
    """
    扫描指定路径下所有文本文件，调用 LLM 检测。
    对超大文件进行截断以避免超过模型最大输入长度；
    一旦发现恶意即返回该结果，否则返回“未检测到恶意”。
    """
    for root, _, files in os.walk(path_to_scan):
        for fname in files:
            if not is_text_file(fname):
                continue
            fullpath = os.path.join(root, fname)
            try:
                with open(fullpath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except Exception as e:
                logging.warning(f"无法读取文件 {fullpath}: {e}")
                continue

            # 截断过长内容
            if len(code) > MAX_CONTENT_LENGTH:
                logging.info(f"文件过大，截断: {fullpath} ({len(code)} 字符)")
                code = code[:MAX_CONTENT_LENGTH]

            prompt = f"""Please help me check whether the following code contains any malicious logic. Respond in JSON format:
{{
  "reason": "...",
  "is_malicious": true|false
}}

Below are the definitions of the attack types and their typical characteristics—if you detect malicious logic, identify which type it belongs to and cite the relevant features:

• Privacy Leakage: access to sensitive information combined with network transmission  
• Malicious Operation: destructive commands (e.g. `rm -rf /*`)  
• Cryptomining Behavior: presence of a cryptocurrency wallet address and network connection to mining pools  
• Remote Code Execution: downloading or transmitting code over the network and executing it  
• Reverse Shell: initiating a network callback plus shell I/O redirection  
• Privilege Escalation: multi-stage behavior (encoding/network/execution) culminating in elevated-privilege code execution  

If the code is malicious, include in the "reason" field:
  1. The specific cause (e.g. backdoor, miner, data leak)  
  2. The code location (file and line/region)  
  3. The attack type (choose one from the list above)  

Set "is_malicious": true.
If not malicious, set "is_malicious": false.

Return **only** the JSON in the following format:

—————— CODE START ——————
{code}
—————— CODE END ——————"""

            try:
                resp = client.chat.completions.create(
                    model="deepseek-v3-250324",
                    messages=[{"role": "user", "content": prompt}]
                )
                text = resp.choices[0].message.content.strip()
                # 提取 JSON 子串再解析
                json_str = extract_json(text)
                result = json.loads(json_str)
                print(result)
            except json.JSONDecodeError:
                logging.warning(f"解析 LLM 输出失败，文件: {fullpath}，原始响应: {text}")
                result = {"reason": "未能解析模型输出，视为无恶意", "is_malicious": False}
            except Exception as e:
                logging.error(f"调用 LLM 失败: {e}")
                result = {"reason": f"检测失败: {e}", "is_malicious": False}

            if result.get("is_malicious"):
                return result
    return {"reason": "未检测到恶意代码", "is_malicious": False}


def main():
    results = []

    # 列出所有项目，并在进度条中显示
    projects = [p for p in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, p))]
    for project in tqdm(projects, desc="Scanning projects", unit="proj"):
        proj_dir = os.path.join(BASE_DIR, project)

        # 查找版本子目录
        subdirs = [
            name for name in os.listdir(proj_dir)
            if os.path.isdir(os.path.join(proj_dir, name))
        ]

        # 如果没有子目录，就把项目目录当成一个“默认版本”
        versions = subdirs if subdirs else [""]
        for ver in versions:
            scan_target = os.path.join(proj_dir, ver) if ver else proj_dir
            logging.info(f"开始扫描: {project} 版本: {ver or 'default'}")
            result = scan_path(scan_target)

            results.append({
                "project": project,
                "version": ver or "default",
                "reason": result["reason"],
                "is_malicious": result["is_malicious"]
            })

        # 每处理完一个项目，就保存一次 JSON
        try:
            with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.error(f"保存扫描结果失败: {e}")

    logging.info(f"扫描完成，结果已保存到：{OUTPUT_PATH}")

if __name__ == "__main__":
    main()