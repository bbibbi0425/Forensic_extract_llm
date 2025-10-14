# LLM Forensic Artifact Extraction Tool
# Filename: cli.py
#
# UI Highlights:
# - All output is in English.
# - Source image hashing is now optional via the --hash flag for faster default execution.
# - Three output modes: default (minimal), color (-c), and verbose (-v).
# - Forensic logging includes source image hash (if requested), tool version, and execution context.
#
# Usage:
#   python -m extract_llm <E01> <MODE> <LLM> <OUTPUT> [-c] [-v] [--hash]

import argparse
import sys
import re
from pathlib import Path
import json
from datetime import datetime
import time
import hashlib

# --- Tool Version Import ---
from extract_llm import __version__

# --- Global Settings ---
IS_MOCK_MODE = False # 테스트용 목업 모드 플래그 (실제 라이브러리 없을 때 대체 동작)

# --- Import Core Libraries & Handle Mock Mode ---
try:
    import pytsk3  # 디스크/파일시스템 포렌식 라이브러리(TSK) 파이썬 바인딩
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True  # pytsk3 불러오기 실패 시 목업 모드로 전환

try:
    if not IS_MOCK_MODE:
        # dfVFS: 다양한 컨테이너(E01 등)와 파일시스템을 추상화해서 접근하게 해주는 라이브러리
        from dfvfs.lib import definitions
        from dfvfs.path import factory as path_spec_factory
        from dfvfs.resolver import resolver as path_spec_resolver
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import dfvfs modules. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True  # dfVFS 불러오기 실패 시도 목업 모드로 전환

# --- Rich Library for UI ---
from rich.console import Console  # 컬러/서식 있는 콘솔 출력
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.box import HEAVY_HEAD
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn  # 진행률 표시

# 전역 콘솔 객체: 인자에 따라 color on/off 설정됨
console = None

# --- Function Definitions ---

def header_panel(image_path, llm_name, mode, output_dir):
    """(Verbose Mode) Displays a header panel with run information."""
    # 실행 요약을 패널로 출력 (verbose 모드에서만)
    text = (
        f"[bold]extract_llm – LLM Forensic Artifact Extraction[/bold]\n\n"
        f"[dim]Analyzing Image:[/dim] {image_path}\n"
        f"[dim]LLM Target:[/dim] {llm_name} ({mode})\n"
        f"[dim]Output Directory:[/dim] {output_dir}"
    )
    panel = Panel(Align.left(text), border_style="cyan", padding=(1, 2))
    console.print(panel)

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    # 대용량 파일도 고려해서 4096바이트 청크 단위로 해시 계산
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, FileNotFoundError):
        return "N/A (File read error)"

def load_artifact_definitions(file_path="artifacts.json"):
    """Loads artifact path definitions from the JSON file."""
    # 스크립트와 같은 디렉토리의 artifacts.json을 읽어 경로/카테고리 정의 로드
    try:
        script_dir = Path(__file__).parent
        config_path = script_dir / file_path
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # 정의 파일 없으면 치명 오류로 종료
        console.print(f"[!] [bold red]FATAL[/bold red]: Artifact definition file not found at '{config_path}'."); sys.exit(1)
    except json.JSONDecodeError:
        # JSON 파싱 실패 시도 치명 오류로 종료
        console.print(f"[!] [bold red]FATAL[/bold red]: Failed to decode JSON from '{config_path}'."); sys.exit(1)

LLM_ARTIFACTS = load_artifact_definitions()  # 전역으로 아티팩트 정의 적재

def normalize_path(path: str) -> str:
    """Normalizes a Windows path to a POSIX-like path and removes the drive letter."""
    # 윈도우 경로(\, 드라이브 문자 등)를 POSIX 스타일(/)로 통일하고 대문자화
    normalized = path.replace('\\', '/')
    if ':' in normalized and (normalized.find(':') < normalized.find('/') if '/' in normalized else True):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')

def get_image_root_entry(image_path: Path):
    """Opens an E01 image and finds the root of the Windows OS partition."""
    # E01 컨테이너를 열고, Windows 디렉터리가 있는 NTFS 파티션의 루트를 찾음
    if IS_MOCK_MODE:
        # 목업: 최소한 디렉터리 인터페이스만 흉내냄
        class MockDir:
            def __init__(self, name): self.name = name
            def _GetSubFileEntries(self): return []
            def IsDirectory(self): return True
        return MockDir(name='\\'), None
    try:
        resolver = path_spec_resolver.Resolver
        os_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=str(image_path))
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_EWF, parent=os_path_spec)  # E01(EWF) 래핑
    except Exception as e:
        console.print(f"[!] [bold red]FATAL[/bold red]: Could not initialize base path specs: {e}")
        return None, None
    # 최대 10개 파티션을 순회하며 'Windows' 폴더 존재 여부로 시스템 파티션 추정
    for i in range(1, 11):
        try:
            partition_location = f'/p{i}'
            partition_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location=partition_location, parent=ewf_path_spec)
            ntfs_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location='/', parent=partition_path_spec)
            fs_root_entry = resolver.OpenFileEntry(ntfs_path_spec)
            if fs_root_entry and fs_root_entry.GetSubFileEntryByName('Windows'):
                console.print(f"[*] Found Windows OS at partition: [bold cyan]{partition_location}[/bold cyan]")
                return fs_root_entry, ntfs_path_spec
        except Exception:
            continue
    console.print("[!] [bold red]FATAL[/bold red]: Could not find a partition containing a 'Windows' directory in the image.")
    return None, None

def log_result(collected_paths, category_key, status, path, error_msg=None):
    """Logs an extraction result to a structured dictionary."""
    # 각 추출 시도 결과를 메모리 내 dict에 누적 (나중에 리포트로 저장)
    result = {"status": status, "path": path, "error_msg": error_msg}
    if category_key not in collected_paths: collected_paths[category_key] = []
    collected_paths[category_key].append(result)

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    """Recursively searches for and requests extraction of files based on path patterns."""
    # 경로 패턴(와일드카드 포함)을 따라 재귀적으로 파일/디렉토리를 탐색 후 추출 요청
    category_key = str(extract_category)
    if not path_parts:
        # 더 내려갈 파트가 없으면 해당 엔트리를 추출 단계로 넘김
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths); return
    current_part, remaining_parts = path_parts[0], path_parts[1:]
    if not root_entry.IsDirectory(): return
    try:
        if current_part == '*':
            # 와일드카드: 현재 디렉토리의 모든 하위 항목 순회
            for sub_entry in root_entry.sub_file_entries:
                if sub_entry.name in ['.', '..']: continue
                recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [sub_entry.name], artifact_info, collected_paths)
        else:
            found_entries = []
            if '*' in current_part:
                # 부분 와일드카드 매칭 (대소문자 무시)
                pattern = re.compile(''.join(map(re.escape, current_part.split('*'))), re.IGNORECASE)
                for entry in root_entry.sub_file_entries:
                    if pattern.match(entry.name): found_entries.append(entry)
            else:
                # 정확 매칭 시도 후, 실패하면 대소문자 무시한 선형 탐색
                entry = root_entry.GetSubFileEntryByName(current_part)
                if not entry:
                    for sub_entry in root_entry.sub_file_entries:
                        if sub_entry.name.lower() == current_part.lower(): entry = sub_entry; break
                if entry: found_entries.append(entry)
            for found_entry in found_entries:
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [found_entry.name], artifact_info, collected_paths)
    except Exception as e:
        # 디렉토리 읽기 실패 상황 로깅
        log_result(collected_paths, category_key, "FAILED", f"/{'/'.join(current_path_parts)}/*", error_msg=f"Could not read directory: {e}")

def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    """Extracts a file or directory to disk."""
    # 실제 파일/디렉토리를 디스크로 복사하는 단계
    original_full_path = '/' + '/'.join(current_path_parts)
    category_key = str(extract_category)
    # 특정 폴더 내 지정된 파일만 추출할 수 있도록 예외 목록 지정이 가능한 로직
    if "extract_files" in artifact_info and entry.IsDirectory():
        try:
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name.upper() in [f.upper() for f in artifact_info["extract_files"]]:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], {"extract_from": sub_entry.name}, collected_paths)
        except Exception as e:
            log_result(collected_paths, category_key, "FAILED", original_full_path, error_msg=f"Failed to list items: {e}")
        return
    # 출력 경로에서 잘린 상대 경로 기준점을 정하기 위한 기준명 계산
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if "{LLM_NAME}" in extract_root_name:
        # 휴리스틱 모드 등에서 LLM 이름 플레이스홀더 치환
        extract_root_name = extract_root_name.replace("{LLM_NAME}", artifact_info.get("llm_name_placeholder", "").upper())
    # 상대 경로 생성: 기준점부터 끝까지
    relative_path_parts = []
    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            start_index = len(upper_path_parts) - 1 - upper_path_parts[::-1].index(extract_root_name)
            relative_path_parts = current_path_parts[start_index:]
        except ValueError: relative_path_parts = [current_path_parts[-1]]
    else: relative_path_parts = [current_path_parts[-1]]
    # 최종 출력 대상 경로 (카테고리/상대경로)
    output_target = Path(output_dir) / extract_category / Path(*relative_path_parts)
    if entry.IsFile():
        # 파일이면 바이트 스트림으로 읽어 그대로 기록 (1MB 청크)
        output_target.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_object = entry.GetFileObject()
            if file_object:
                with open(output_target, 'wb') as outfile:
                    chunk = file_object.read(1024 * 1024)
                    while chunk: outfile.write(chunk); chunk = file_object.read(1024 * 1024)
                file_object.close()
            log_result(collected_paths, category_key, "SUCCESS", original_full_path)
        except Exception as e: log_result(collected_paths, category_key, "FAILED", original_full_path, error_msg=f"Failed to write file: {e}")
    elif entry.IsDirectory():
        # 디렉토리는 폴더만 생성 후 하위 항목 재귀 처리
        output_target.mkdir(parents=True, exist_ok=True)
        log_result(collected_paths, category_key, "SUCCESS", original_full_path)
        try:
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], artifact_info, collected_paths)
        except Exception as e: log_result(collected_paths, category_key, "FAILED", f"{original_full_path}/{sub_entry.name}", error_msg=f"Failed to process subdirectory item: {e}")

def final_summary(collected_paths, program_output_dir, path_log_file_path, verbose=False, keep_plus=True):
    """Displays the final summary message after extraction."""
    # 최종 요약 출력 (verbose면 카테고리별 표, 기본은 경로 안내만)
    if verbose:
        console.print()
        table = Table(title=Align.center("Artifact Extraction Summary"), show_header=True, header_style="bold", box=HEAVY_HEAD)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Succeeded", justify="right")
        table.add_column("Failed", justify="right")
        total_succeeded, total_failed = 0, 0
        for category_key, results in sorted(collected_paths.items()):
            succeeded = sum(1 for r in results if r['status'] == 'SUCCESS')
            failed = len(results) - succeeded
            total_succeeded += succeeded
            total_failed += failed
            label = category_key if keep_plus else category_key.replace("+", "_")
            failed_str = f"[red]{failed}[/red]" if failed > 0 else str(failed)
            table.add_row(label, str(succeeded), failed_str)
        console.print(table)
        fail_msg = f"with [bold red]{total_failed}[/bold red] failures." if total_failed > 0 else "without any errors."
        console.print(f"\n[*] [bold]Analysis complete.[/bold] Successfully extracted [bold green]{total_succeeded}[/bold green] artifacts {fail_msg}")
    # 요약 경로 안내
    console.print("\n[*] Processing complete.")
    console.print(f"    - Extracted files are in: [cyan]{program_output_dir.resolve()}[/cyan]")
    console.print(f"    - See the full report at: [cyan]{path_log_file_path.resolve()}[/cyan]")

def write_extracted_paths_log(collected_paths, program_output_dir, image_name, image_hash, llm_name, mode, tool_version, command_line, execution_time, keep_plus=True):
    """Writes all extracted paths and failures to a detailed log file."""
    # 상세 리포트(extraction_report.txt) 작성: 실행 메타데이터 + 카테고리/경로별 성공/실패 내역
    path_log_file_path = program_output_dir / "extraction_report.txt"
    total_succeeded = sum(1 for res_list in collected_paths.values() for res in res_list if res['status'] == 'SUCCESS')
    total_failed = sum(1 for res_list in collected_paths.values() for res in res_list if res['status'] == 'FAILED')
    with open(path_log_file_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f" extract_llm - LLM Forensic Artifact Extraction Log (v{tool_version})\n")
        f.write("=" * 70 + "\n\n")
        f.write("Run Details\n" + "-----------\n")
        f.write(f"- Source Image: {image_name}\n- Source Image SHA-256: {image_hash}\n- LLM Target: {llm_name} (Mode: {mode})\n")
        f.write(f"- Output Directory: {program_output_dir.resolve()}\n- Command Line: {' '.join(command_line)}\n- Timestamp: {datetime.now().isoformat()}\n\n")
        f.write("Extraction Summary\n" + "------------------\n")
        f.write(f"- Categories Processed: {len(collected_paths)}\n- Successful Extractions: {total_succeeded}\n- Failed Extractions: {total_failed}\n")
        f.write(f"- Total Execution Time: {execution_time:.2f} seconds\n\n")
        f.write("=" * 70 + "\n" + " Detailed Path Log\n" + "=" * 70 + "\n")
        for category_key, results in sorted(collected_paths.items()):
            header = category_key if keep_plus else category_key.replace('+', '_')
            succeeded = sum(1 for r in results if r['status'] == 'SUCCESS')
            failed = len(results) - succeeded
            f.write(f"\n\n## Category: {header} ({succeeded} succeeded, {failed} failed)\n" + "-" * 70 + "\n")
            if not results: f.write("- No paths found for this category.\n"); continue
            for res in sorted(results, key=lambda r: (r['status'] == 'FAILED', r['path'])):
                if res['status'] == 'SUCCESS': f.write(f"[SUCCESS]  {res['path']}\n")
                else: f.write(f"[FAILED]   {res['path']}\n           Reason: {res['error_msg']}\n")
        f.write("\n\n--- End of Report ---\n")
    return path_log_file_path

def parse_args():
    """Parses command-line arguments."""
    # CLI 인자 파서: 모드/LLM 이름/출력 폴더 및 옵션(-c, -v, --hash, -p, -s)
    parser = argparse.ArgumentParser(
        description="extract_llm: Extracts forensic artifacts of LLM applications from an E01 image.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result -c\n  python %(prog)s ./E01/CLAUDE.E01 api CLAUDE ./result -v --hash"
    )
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed.")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode.")
    parser.add_argument("LLM_NAME", help="Name of the LLM program to extract artifacts from.")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved.")
    parser.add_argument("-c", "--color", action="store_true", help="Enable colorized output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (implies color).")
    parser.add_argument("--hash", action="store_true", help="Calculate and log the SHA-256 hash of the source image (can be slow).")
    parser.add_argument("-p", "--no-keep-plus", action="store_true", help="Replace '+' with '_' in category folder names.")
    parser.add_argument("-s", "--no-final-summary", action="store_true", help="Disable the final summary message.")
    return parser.parse_args()

def main():
    """The main execution function."""
    # 메인 진입점: 인자 파싱 → 콘솔 설정 → 이미지 검증 → 정의 로드 → 탐색/추출 → 리포트/요약
    global console
    start_time = time.time()
    args = parse_args()
    
    # verbose면 자동으로 color 활성화
    use_color = args.color or args.verbose
    console = Console(no_color=not use_color)
    
    if IS_MOCK_MODE: console.print("[!] [yellow]Warning[/yellow]: Running in Mock Mode.")

    e01_image_path = Path(args.E01_IMAGE_PATH)
    if not e01_image_path.is_file() and not IS_MOCK_MODE:
        # 실제 파일 존재 확인 (목업 모드면 스킵)
        console.print(f"\n[!] [red]Error[/red]: The specified E01 image file does not exist: {e01_image_path.resolve()}"); sys.exit(1)

    llm_name_upper = args.LLM_NAME.upper()
    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        header_panel(args.E01_IMAGE_PATH, llm_name_upper, args.MODE, str(program_output_dir.resolve()))
    else:
        console.print(f"[*] Processing: [bold cyan]{args.E01_IMAGE_PATH}[/bold cyan] for [bold cyan]{llm_name_upper}[/bold cyan] artifacts...")
    
    image_hash = "N/A (Skipped by user)"
    if args.hash:
        # --hash 옵션 지정 시 원본 이미지 SHA-256 계산
        console.print("[*] Calculating source image SHA-256 (this may take a while)...")
        image_hash = "N/A (Mock Mode)" if IS_MOCK_MODE else calculate_sha256(e01_image_path)
        console.print(f"[*] Source image SHA-256: [cyan]{image_hash}[/cyan]")

    # 지정한 LLM 이름이 사전 정의에 있는지 확인, 없으면 휴리스틱 모드 사용
    is_defined_llm = llm_name_upper in LLM_ARTIFACTS
    is_heuristic_mode = not is_defined_llm
    if is_heuristic_mode:
        heuristic_key = f"_HEURISTICS_{args.MODE.upper()}"
        if heuristic_key not in LLM_ARTIFACTS:
            console.print(f"\n[!] [red]Error[/red]: Heuristic definition '{heuristic_key}' not found for '{args.LLM_NAME}'."); sys.exit(1)
        artifacts_to_extract = LLM_ARTIFACTS[heuristic_key]
        console.print("[!] [yellow]Warning[/yellow]: Running in Heuristic Discovery Mode.")
    else: artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    
    # E01에서 Windows 파티션 루트 엔트리 획득
    root_entry, _ = get_image_root_entry(e01_image_path)
    if root_entry is None: sys.exit(1)

    collected_paths = {}  # 추출 결과 누적 저장소
    # 진행률 UI 표시하면서 카테고리별 처리
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console, transient=True) as progress:
        task_description = "[cyan]Processing categories...[/cyan]" if args.verbose else "[cyan]Processing artifacts...[/cyan]"
        task = progress.add_task(task_description, total=len(artifacts_to_extract))
        for category, artifacts in artifacts_to_extract.items():
            if args.verbose: progress.update(task, description=f"[cyan]Processing: {category.replace('_', ' ')}...[/cyan]")
            category_key = category if not args.no_keep_plus else category.replace('+', '_')
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                if is_heuristic_mode:
                    # 휴리스틱 정의에 포함된 {LLM_NAME} 플레이스홀더를 실제 입력값으로 치환
                    full_path = full_path.replace("{LLM_NAME}", llm_name_upper)
                    artifact_info["llm_name_placeholder"] = llm_name_upper
                # 정규화된 경로를 분해하여 재귀 탐색+추출
                recursive_search_and_extract(root_entry, normalize_path(full_path).split('/'), program_output_dir, Path(category_key), [], artifact_info, collected_paths)
            if IS_MOCK_MODE: time.sleep(0.5)  # 목업 모드에서 진행률 가짜 지연
            progress.update(task, advance=1)
            
    # verbose 모드에서는 카테고리별 성공/실패 요약을 한 번 더 표시
    if args.verbose:
        console.print("\n[*] Extraction process finished. Finalizing results...")
        for category_key, results in sorted(collected_paths.items()):
            succeeded = sum(1 for r in results if r['status'] == 'SUCCESS')
            failed = len(results) - succeeded
            label = category_key.replace('_', ' ')
            if failed > 0: console.print(f"[!] [red]ALERT[/red]: {label}: {succeeded} succeeded, {failed} failed")
            else: console.print(f"[*] [green]INFO[/green]:  {label}: {succeeded} succeeded, 0 failed")

    # 실행 시간 측정 및 리포트 파일 기록
    execution_time = time.time() - start_time
    path_log_file_path = write_extracted_paths_log(collected_paths, program_output_dir, e01_image_path.name, image_hash, llm_name_upper, args.MODE, __version__, sys.argv, execution_time, not args.no_keep_plus)
    
    # 최종 요약 출력(비활성화 옵션 -s 없으면)
    if not args.no_final_summary:
        final_summary(collected_paths, program_output_dir, path_log_file_path, verbose=args.verbose, keep_plus=not args.no_keep_plus)

if __name__ == "__main__":
    main()
