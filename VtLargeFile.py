import requests
import json
import time
import os
from datetime import datetime
import hashlib

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        self.timeout = (30, 300)  # 连接超时30秒，读取超时5分钟
        # 速率限制：4次请求/分钟
        self.request_interval = 15  # 每15秒一次请求
        self.last_request_time = 0
        self.daily_request_count = 0
        self.max_daily_requests = 500
        # 大文件上传限制 - 修正为正确的限制
        self.max_small_size = 32 * 1024 * 1024  # 32MB
        self.max_large_size = 650 * 1024 * 1024  # 650MB (VirusTotal限制)
        # 缓存已查询结果
        self.results_cache = {}

    def _wait_for_rate_limit(self):
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.request_interval:
            wait = self.request_interval - elapsed
            print(f"等待 {wait:.1f} 秒以符合速率限制...")
            time.sleep(wait)
        self.last_request_time = time.time()
        self.daily_request_count += 1
        if self.daily_request_count >= self.max_daily_requests:
            print("已达到每日请求限制！")
            return False
        print(f"今日已使用请求数: {self.daily_request_count}/{self.max_daily_requests}")
        return True

    def get_file_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def check_existing_report(self, file_hash):
        if not self._wait_for_rate_limit():
            return None
        url = f"{self.base_url}files/{file_hash}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            else:
                resp.raise_for_status()
        except Exception as e:
            print(f"检查现有报告时出错: {e}")
            return None

    def _get_large_file_upload_url(self):
        """获取大文件上传 URL"""
        if not self._wait_for_rate_limit():
            return None

        try:
            response = requests.get(
                f"{self.base_url}files/upload_url",
                headers=self.headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            upload_url = response.json().get('data')
            print(f"获取到大文件上传URL: {upload_url}")
            return upload_url
        except Exception as e:
            print(f"获取大文件上传URL失败: {e}")
            return None

    def upload_file(self, file_path):
        # 检查文件大小
        file_size = os.path.getsize(file_path)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"文件大小: {file_size_mb:.2f} MB")
        
        # 检查是否超过最大限制
        if file_size > self.max_large_size:
            print(f"文件过大 ({file_size_mb:.2f} MB)，超过VirusTotal限制 ({self.max_large_size/(1024*1024)} MB)")
            return None

        file_hash = self.get_file_hash(file_path)
        
        # 检查缓存
        if file_hash in self.results_cache:
            print(f"从缓存获取结果: {file_hash}")
            return self.results_cache[file_hash]
            
        # 检查是否已有报告
        existing = self.check_existing_report(file_hash)
        if existing:
            print("找到已有分析结果")
            self.results_cache[file_hash] = existing
            return existing

        # 根据文件大小选择上传方式
        if file_size <= self.max_small_size:
            print("使用小文件上传接口")
            result = self._upload_small_file(file_path)
        else:
            print("使用大文件上传接口")
            result = self._upload_large_file(file_path)

        if result:
            self.results_cache[file_hash] = result
        return result

    def _upload_small_file(self, file_path):
        if not self._wait_for_rate_limit():
            return None
        
        print(f"上传小文件: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                resp = requests.post(
                    self.base_url + "files", 
                    headers=self.headers, 
                    files=files, 
                    timeout=self.timeout
                )
                resp.raise_for_status()
                return resp.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 413:
                print("文件太大，尝试大文件上传接口...")
                return self._upload_large_file(file_path)
            else:
                print(f"上传小文件失败: {e}")
                return None
        except Exception as e:
            print(f"上传小文件失败: {e}")
            return None

    def _upload_large_file(self, file_path):
        print(f"准备大文件上传: {os.path.basename(file_path)}")
        
        # 获取上传URL
        upload_url = self._get_large_file_upload_url()
        if not upload_url:
            print("无法获取大文件上传URL")
            return None

        max_retries = 3
        for attempt in range(max_retries):
            try:
                print(f"开始上传大文件 (尝试 {attempt + 1}/{max_retries})...")
                
                # 准备上传
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    
                    # 大文件上传使用更长的超时时间
                    upload_timeout = (60, 1800)  # 连接60秒，读取30分钟
                    
                    response = requests.post(
                        upload_url,
                        files=files,
                        headers={"x-apikey": self.api_key},
                        timeout=upload_timeout
                    )
                    
                    response.raise_for_status()
                    print("大文件上传成功!")
                    return response.json()
                    
            except requests.exceptions.Timeout:
                print(f"上传超时 (尝试 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    wait_time = 30 * (attempt + 1)
                    print(f"等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    print("达到最大重试次数，上传失败")
                    return None
                    
            except requests.exceptions.HTTPError as e:
                print(f"HTTP错误 (尝试 {attempt + 1}/{max_retries}): {e}")
                if e.response.status_code == 413:
                    print("文件仍然太大，无法上传")
                    return None
                elif attempt < max_retries - 1:
                    time.sleep(30)
                else:
                    return None
                    
            except Exception as e:
                print(f"上传错误 (尝试 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(30)
                else:
                    return None

        return None

    def get_analysis(self, analysis_id):
        if not self._wait_for_rate_limit():
            return None
        
        max_attempts = 30  # 增加等待次数
        for attempt in range(max_attempts):
            try:
                url = f"{self.base_url}analyses/{analysis_id}"
                resp = requests.get(url, headers=self.headers, timeout=self.timeout)
                resp.raise_for_status()

                analysis_result = resp.json()
                status = analysis_result['data']['attributes']['status']
                
                print(f"分析状态: {status} ({attempt + 1}/{max_attempts})")
                
                if status == 'completed':
                    return analysis_result
                elif status in ['queued', 'in_progress']:
                    time.sleep(60)  # 等待1分钟
                    continue
                else:
                    print(f"分析状态异常: {status}")
                    return None

            except Exception as e:
                print(f"获取分析结果失败: {e}")
                if attempt < max_attempts - 1:
                    time.sleep(30)
                    continue
                return None

        print(f"分析等待超时，ID: {analysis_id}")
        return None

    def get_file_report(self, file_hash):
        if not self._wait_for_rate_limit():
            return None
        try:
            resp = requests.get(
                self.base_url + f"files/{file_hash}", 
                headers=self.headers, 
                timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"获取最终报告失败: {e}")
            return None


def save_report(report_data, output_file):
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        print(f"报告已保存: {output_file}")
        return True
    except Exception as e:
        print(f"保存报告失败: {e}")
        return False


def load_processed_files(log_file):
    processed = set()
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    processed.add(line.strip())
        except Exception as e:
            print(f"加载处理记录失败: {e}")
    return processed


def save_processed_file(log_file, filename):
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{filename}\n")
    except Exception as e:
        print(f"记录处理文件失败: {e}")


def batch_analyze_apks(api_key, apk_directory, output_directory):
    os.makedirs(output_directory, exist_ok=True)
    log_file = os.path.join(output_directory, "processed_files.log")
    cache_file = os.path.join(output_directory, "results_cache.json")
    error_log_file = os.path.join(output_directory, "error_files.log")

    processed = load_processed_files(log_file)
    vt = VirusTotalAPI(api_key)

    # 加载缓存
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                vt.results_cache = json.load(f)
            print(f"加载缓存: {len(vt.results_cache)} 个结果")
        except Exception as e:
            print(f"加载缓存失败: {e}")

    apk_files = [f for f in os.listdir(apk_directory)
                 if f.lower().endswith('.apk') and f not in processed]

    print(f"找到 {len(apk_files)} 个待处理 APK 文件")
    
    for idx, apk in enumerate(apk_files, start=1):
        apk_path = os.path.join(apk_directory, apk)
        print(f"\n{'='*60}")
        print(f"[{idx}/{len(apk_files)}] 处理: {apk}")
        print(f"{'='*60}")

        try:
            file_hash = vt.get_file_hash(apk_path)
            print(f"SHA256: {file_hash}")
            output_file = os.path.join(output_directory, f"{apk.replace('.apk','')}_{file_hash[:8]}.json")

            if os.path.exists(output_file):
                print("报告已存在，跳过")
                save_processed_file(log_file, apk)
                continue

            # 上传文件
            result = vt.upload_file(apk_path)
            if not result:
                print("上传失败，记录到错误日志")
                with open(error_log_file, "a", encoding="utf-8") as f:
                    f.write(f"{apk}: 上传失败\n")
                continue

            # 检查是否是已有分析结果
            if 'data' in result and 'attributes' in result['data']:
                # 这是完整的分析报告
                if save_report(result, output_file):
                    save_processed_file(log_file, apk)
                    print("处理完成（使用已有报告）")
                continue

            # 新上传的文件，需要等待分析
            analysis_id = result.get("data", {}).get("id")
            if not analysis_id:
                print("未获取到分析ID")
                continue
                
            print(f"上传成功，analysis_id: {analysis_id}")
            print("等待分析完成...")

            # 等待分析完成
            analysis_result = vt.get_analysis(analysis_id)
            if analysis_result and analysis_result['data']['attributes']['status'] == 'completed':
                # 获取最终报告
                final_report = vt.get_file_report(file_hash)
                if final_report and save_report(final_report, output_file):
                    save_processed_file(log_file, apk)
                    print("处理完成")
                else:
                    print("获取最终报告失败")
            else:
                print("分析未完成或失败")

        except Exception as e:
            print(f"处理 {apk} 时发生错误: {e}")
            with open(error_log_file, "a", encoding="utf-8") as f:
                f.write(f"{apk}: {str(e)}\n")
            continue

        # 检查API配额
        if vt.daily_request_count >= vt.max_daily_requests:
            print("达到每日配额，停止处理")
            break

        # 定期保存缓存
        if idx % 5 == 0:
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(vt.results_cache, f, ensure_ascii=False, indent=2)
                print("缓存已保存")
            except Exception as e:
                print(f"保存缓存失败: {e}")

    # 保存最终缓存
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(vt.results_cache, f, ensure_ascii=False, indent=2)
        print("最终缓存已保存")
    except Exception as e:
        print(f"保存最终缓存失败: {e}")

    print(f"\n批量分析完成！今日使用请求数: {vt.daily_request_count}/{vt.max_daily_requests}")


def main():
    API_KEY = "YOU_API_KEY"
    APK_DIRECTORY = "APK_DIRECTORY"
    OUTPUT_DIRECTORY = "RESULT_DIRECTORY"

    if not os.path.exists(APK_DIRECTORY):
        print(f"APK 目录不存在: {APK_DIRECTORY}")
        return

    batch_analyze_apks(API_KEY, APK_DIRECTORY, OUTPUT_DIRECTORY)


if __name__ == "__main__":
    main()
