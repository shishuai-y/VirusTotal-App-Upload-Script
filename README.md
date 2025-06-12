# VirusTotal APK Batch Analyzer / VirusTotal APK 批量上传分析脚本

##  English

### Project Overview

This Python script provides a robust solution for batch uploading Android APK files to the VirusTotal platform for analysis. It is designed to handle API limitations gracefully, manage large directories of apps, and ensure that work can be resumed if interrupted. The script intelligently checks for existing reports to save API quota, handles both small and large file uploads, and caches results for efficiency.

### Features

-   **Batch Processing**: Automatically finds and processes all APK files within a specified directory.
-   **Smart Uploading**: Before uploading, it calculates the file's SHA256 hash and checks if a report already exists on VirusTotal, saving API calls.
-   **Handles Large & Small Files**: Automatically uses the appropriate VirusTotal API endpoint based on file size (small files < 32MB, large files > 32MB).
-   **Rate Limit & Quota Management**: Strictly adheres to the public API rate limit (4 requests/minute) and stops automatically when the daily quota (500 requests/day) is reached.
-   **Resumption Support**: Keeps a log (`processed_files.log`) of completed files, allowing the script to be stopped and restarted without re-processing files.
-   **Result Caching**: Caches all fetched reports (`results_cache.json`) to prevent redundant API calls on subsequent runs.
-   **Robust Error Handling**: Includes retries for large file uploads and logs any files that fail during the process to `error_files.log`.
-   **Organized Output**: Saves each analysis report as a separate JSON file in a designated output directory.

### Prerequisites

You need to have the `requests` library installed.
```bash
pip install requests
```

### Configuration

Before running the script, you must configure the following variables in the `main()` function at the bottom of the script:

1.  `API_KEY`: Your personal VirusTotal API key.
2.  `APK_DIRECTORY`: The full path to the directory containing the APK files you want to analyze.
3.  `OUTPUT_DIRECTORY`: The full path to the directory where the JSON reports and log files will be saved.

```python
def main():
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
    APK_DIRECTORY = "/path/to/your/apks"
    OUTPUT_DIRECTORY = "/path/to/your/results"
    
    # ...
```

### Usage

Once configured, run the script from your terminal:
```bash
python your_script_name.py
```
The script will then begin processing the files in the `APK_DIRECTORY`.

### How It Works

The script follows this workflow for each APK file:
1.  **Scan Directory**: Identifies all `.apk` files in the source directory that are not listed in `processed_files.log`.
2.  **Calculate Hash**: Computes the SHA256 hash of the APK.
3.  **Check Cache**: Checks the local `results_cache.json` for a pre-existing result for this hash.
4.  **Check VirusTotal**: If not in the cache, it queries the VirusTotal API for an existing report using the hash.
5.  **Upload (If Needed)**: If no report exists, the script uploads the file. It automatically selects the correct method based on file size.
6.  **Poll for Analysis**: For new uploads, it polls the analysis endpoint until the status is "completed".
7.  **Fetch & Save Report**: Once the analysis is complete, it fetches the final file report and saves it as a formatted JSON file.
8.  **Log Progress**: The filename is added to `processed_files.log` to mark it as complete. The result is saved to the local cache.

---

## 中文

### 项目简介

这是一个功能强大的 Python 脚本，用于将安卓应用（APK 文件）批量上传至 VirusTotal 平台进行安全分析。该脚本经过精心设计，能够优雅地处理 API 的各种限制、管理包含大量应用的目录，并确保在中断后可以恢复工作。脚本会智能地检查已有报告以节省 API 配额，自动处理大小不同的文件，并缓存结果以提高效率。

### 功能特性

-   **批量处理**：自动发现并处理指定目录下的所有 APK 文件。
-   **智能上传**：在上传前，脚本会计算文件的 SHA256 哈希值，并检查 VirusTotal上是否已存在分析报告，从而节省 API 调用次数。
-   **支持大/小文件**：根据文件大小（小于32MB/大于32MB），自动选择最合适的 VirusTotal API 接口进行上传。
-   **速率与配额管理**：严格遵守公共 API 的速率限制（4次/分钟），并在达到每日配额（500次/天）后自动停止。
-   **断点续传**：通过日志文件 (`processed_files.log`) 记录已处理完成的文件，允许用户随时停止和重启脚本，无需担心重复处理。
-   **结果缓存**：将所有获取到的报告缓存至本地 (`results_cache.json`)，避免在后续运行中产生冗余的 API 请求。
-   **强大的错误处理**：包含大文件上传的重试机制，并将处理失败的文件记录到错误日志 (`error_files.log`) 中。
-   **结构化输出**：将每个应用的分析报告作为一个独立的 JSON 文件，保存在指定的输出目录中。

### 环境要求

您需要安装 `requests` 库。
```bash
pip install requests
```

### 配置说明

在运行脚本前，您必须修改位于脚本底部的 `main()` 函数中的以下三个变量：

1.  `API_KEY`: 您的个人 VirusTotal API 密钥。
2.  `APK_DIRECTORY`: 包含待分析 APK 文件的目录的完整路径。
3.  `OUTPUT_DIRECTORY`: 用于保存 JSON 报告和日志文件的目录的完整路径。

```python
def main():
    API_KEY = "在这里填入您的VirusTotal API密钥"
    APK_DIRECTORY = "/path/to/your/apks"  # 例如 "C:\\Users\\YourUser\\Downloads\\APKs"
    OUTPUT_DIRECTORY = "/path/to/your/results" # 例如 "C:\\Users\\YourUser\\Downloads\\Results"
    
    # ...
```

### 如何使用

配置完成后，在您的终端或命令行中运行脚本：
```bash
python your_script_name.py
```
脚本将开始自动处理 `APK_DIRECTORY` 目录中的文件。

### 工作流程

脚本对每个 APK 文件遵循以下工作流程：
1.  **扫描目录**：识别源目录中所有未被 `processed_files.log` 记录过的 `.apk` 文件。
2.  **计算哈希**：计算 APK 文件的 SHA256 哈希值。
3.  **检查缓存**：在本地的 `results_cache.json` 文件中查找该哈希是否已存在结果。
4.  **查询VT**：如果本地无缓存，则使用哈希值向 VirusTotal API 查询是否已存在报告。
5.  **上传文件** (如需)：如果云端无报告，脚本将根据文件大小自动选择合适的方法上传文件。
6.  **轮询分析状态**：对于新上传的文件，脚本会轮询分析接口，直到分析状态变为“completed”。
7.  **获取并保存报告**：分析完成后，获取最终的文件报告并存为格式化的 JSON 文件。
8.  **记录进度**：将文件名写入 `processed_files.log`，并将结果存入本地缓存，标记为处理完毕。
