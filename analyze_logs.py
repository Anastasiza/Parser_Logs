import os
import re
import json
import argparse
from collections import defaultdict, Counter

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]+)" "(?P<agent>[^"]+)" (?P<duration>\d+)'
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def analyze_logs(file_path):
    stats = {
        "total_requests": 0,
        "methods": Counter(),
        "ip_counter": Counter(),
        "longest_requests": []
    }

    with open(file_path, 'r') as file:
        for line in file:
            data = parse_log_line(line)
            if data:
                stats["total_requests"] += 1
                stats["methods"][data["method"]] += 1
                stats["ip_counter"][data["ip"]] += 1

                duration = int(data["duration"])
                request_info = {
                    "method": data["method"],
                    "url": data["url"],
                    "ip": data["ip"],
                    "duration": duration,
                    "time": data["time"]
                }

                stats["longest_requests"].append(request_info)
                stats["longest_requests"].sort(key=lambda x: x["duration"], reverse=True)
                if len(stats["longest_requests"]) > 3:
                    stats["longest_requests"].pop()

    stats["top_ips"] = {ip: count for ip, count in stats["ip_counter"].most_common(3)}
    stats["top_longest"] = stats["longest_requests"][:3]
    stats["total_stat"] = dict(stats["methods"])

    return stats

def process_directory(directory_path):
    results = {}
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            print(f"Обработка файла: {file_path}")
            results[filename] = analyze_logs(file_path)
    return results

def save_results(results, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for filename, data in results.items():
        output_file = os.path.join(output_dir, f"{filename}.json")
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Результаты сохранены в {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Анализировать файлы логов доступа.")
    parser.add_argument("path", default="/logs", help="Путь к файлу лога или директории, содержащей файлы логов")
    parser.add_argument("--output-dir", default="output", help="Директория для сохранения результатов в формате JSON")
    args = parser.parse_args()

    if os.path.isfile(args.path):
        results = {os.path.basename(args.path): analyze_logs(args.path)}
        for result in results.values():
            print(json.dumps(result, indent=4, ensure_ascii=False))
    elif os.path.isdir(args.path):
        results = process_directory(args.path)
        for result in results.values():
            print(json.dumps(result, indent=4, ensure_ascii=False))
    else:
        print(f"Неверный путь: {args.path}")
        return

    save_results(results, args.output_dir)

if __name__ == "__main__":
    main()
