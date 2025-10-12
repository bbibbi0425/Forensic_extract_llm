# LLM Forensic Artifact Extraction Tool
# Filename: extract_llm.py
#
# UI Highlights:
# - Three output modes: default (minimal), color (-c), and verbose (-v).
# - Single-letter flags for concise command-line usage.
# - Verbose mode brings back the detailed header, per-category summary, and final table for in-depth analysis.
# - Forensic logging includes source image hash, tool version, and execution context.
#
# Usage:
#   python extract_llm.py <E01> <MODE> <LLM> <OUTPUT> [-c] [-v] [-p] [-s]


import argparse
import sys
import re
from pathlib import Path
import json
from datetime import datetime
import time
import hashlib

# --- 도구 버전 임포트 ---
# 패키지 수준에서 정의된 도구 버전(__version__)을 가져옴
from extract_llm import __version__

# --- 전역 설정 ---
# 실제 라이브러리 로딩 실패 시 모의(Mock) 모드로 전환하기 위한 플래그
IS_MOCK_MODE = False

# --- 필수 라이브러리 임포트 및 목 모드 설정 ---
# Sleuth Kit의 Python 바인딩(pytsk3) 로드 시도. 실패하면 목 모드로 전환.
try:
    import pytsk3
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

# dfVFS 관련 모듈 로드 시도. 실패하면 목 모드로 전환.
try:
    if not IS_MOCK_MODE:
        from dfvfs.lib import definitions
        from dfvfs.path import factory as path_spec_factory
        from dfvfs.resolver import resolver as path_spec_resolver
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import dfvfs modules. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

# --- UI 및 콘솔 출력을 위한 Rich 라이브러리 설정 ---
# 콘솔 스타일 출력(패널/테이블/프로그레스바 등)용 라이브러리
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.box import HEAVY_HEAD
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# console 객체는 main()에서 옵션에 따라 color/mono가 결정.
console = None

# --- 함수 정의 ---

def header_panel(image_path, llm_name, mode, output_dir):
    # (Verbose Mode) 프로그램 시작 시 실행 정보를 보여주는 헤더 패널을 출력하는 함수.
    text = (
        f"[bold]extract_llm – LLM Forensic Artifact Extraction[/bold]\n"
        f"\n"
        f"[dim]Analyzing Image:[/dim] {image_path}\n"
        f"[dim]LLM Target:[/dim] {llm_name} ({mode})\n"
        f"[dim]Output Directory:[/dim] {output_dir}"
    )
    panel = Panel(Align.left(text), border_style="cyan", padding=(1,2))
    console.print(panel)

def calculate_sha256(file_path):
    # 파일의 SHA256 해시를 계산하는 함수.
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, FileNotFoundError):
        return "N/A (Error reading file)"

def load_artifact_definitions(file_path="artifacts.json"):
    # 아티팩트 경로 정보가 담긴 JSON 파일을 로드하는 함수.
    try:
        script_dir = Path(__file__).parent
        config_path = script_dir / file_path
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[!] [bold red]FATAL[/bold red]: Artifact definition file not found at '{config_path}'."); sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[!] [bold red]FATAL[/bold red]: Failed to decode JSON from '{config_path}'."); sys.exit(1)

# 전역 아티팩트 정의(artifacts.json 로드)
LLM_ARTIFACTS = load_artifact_definitions()

def normalize_path(path: str) -> str:
    # 경로 구분자 통일(백슬래시→슬래시) 및 드라이브 문자 제거 후 대문자 표준화
    normalized = path.replace('\\', '/')
    if ':' in normalized and (normalized.find(':') < normalized.find('/') if '/' in normalized else True):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')

def get_image_root_entry(image_path: Path):
    # E01 이미지에서 Windows 디렉터리가 존재하는 NTFS 파티션(p1~p10)을 탐색하여
    # 루트 엔트리(FileEntry)와 해당 NTFS path spec을 반환.
    if IS_MOCK_MODE:
        class MockDir:
            def __init__(self, name): self.name = name
            def _GetSubFileEntries(self): return []
            def IsDirectory(self): return True
        return MockDir(name='\\'), None
    try:
        resolver = path_spec_resolver.Resolver
        os_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=str(image_path))
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_EWF, parent=os_path_spec)
    except Exception as e:
        console.print(f"[!] [bold red]FATAL[/bold red]: Could not initialize base path specs: {e}")
        return None, None
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
    # 추출 성공/실패 결과를 카테고리별 리스트에 축적.
    result = {"status": status, "path": path, "error_msg": error_msg}
    if category_key not in collected_paths: collected_paths[category_key] = []
    collected_paths[category_key].append(result)

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    # 와일드카드('*')와 대소문자 무시 매칭을 지원하는 재귀 탐색/추출 루틴.
    #     - path_parts: 남은 경로 토큰 리스트
    #     - current_path_parts: 현재까지 누적된 경로 토큰
    #     - artifact_info: 아티팩트 정의(선택 추출 목록, 루트 기준 등 포함)
    category_key = str(extract_category)
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths); return
    current_part, remaining_parts = path_parts[0], path_parts[1:]
    if not root_entry.IsDirectory(): return
    try:
        if current_part == '*':
            for sub_entry in root_entry.sub_file_entries:
                if sub_entry.name in ['.', '..']: continue
                recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [sub_entry.name], artifact_info, collected_paths)
        else:
            found_entries = []
            if '*' in current_part:
                # 간단한 와일드카드 매칭(정규표현식 변환)
                pattern = re.compile(''.join(map(re.escape, current_part.split('*'))), re.IGNORECASE)
                for entry in root_entry.sub_file_entries:
                    if pattern.match(entry.name): found_entries.append(entry)
            else:
                # 정확 매칭 → 대소문자 무시 보조 탐색
                entry = root_entry.GetSubFileEntryByName(current_part)
                if not entry:
                    for sub_entry in root_entry.sub_file_entries:
                        if sub_entry.name.lower() == current_part.lower(): entry = sub_entry; break
                if entry: found_entries.append(entry)
            for found_entry in found_entries:
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [found_entry.name], artifact_info, collected_paths)
    except Exception as e:
        log_result(collected_paths, category_key, "FAILED", f"/{'/'.join(current_path_parts)}/*", error_msg=f"Could not read directory: {e}")

def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    # 파일/디렉토리를 실제로 복사(추출)하는 함수
    original_full_path = '/' + '/'.join(current_path_parts)
    category_key = str(extract_category)
    # 특정 하위 항목만 선택적으로 추출해야 하는 경우("extract_files") 처리
    if "extract_files" in artifact_info and entry.IsDirectory():
        try:
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name.upper() in [f.upper() for f in artifact_info["extract_files"]]:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], {"extract_from": sub_entry.name}, collected_paths)
        except Exception as e:
            log_result(collected_paths, category_key, "FAILED", original_full_path, error_msg=f"Failed to list items: {e}")
        return
    # 결과 저장 경로를 구성하기 위한 루트 기준명 계산 (extract_from)
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if "{LLM_NAME}" in extract_root_name:
        extract_root_name = extract_root_name.replace("{LLM_NAME}", artifact_info.get("llm_name_placeholder", "").upper())
    # 상대 경로 생성 로직: 지정된 루트명부터의 부분 경로만 보존
    relative_path_parts = []
    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            start_index = len(upper_path_parts) - 1 - upper_path_parts[::-1].index(extract_root_name)
            relative_path_parts = current_path_parts[start_index:]
        except ValueError: relative_path_parts = [current_path_parts[-1]]
    else: relative_path_parts = [current_path_parts[-1]]
    output_target = Path(output_dir) / extract_category / Path(*relative_path_parts)
    if entry.IsFile():
        output_target.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_object = entry.GetFileObject()
            if file_object:
                # 1MB 단위로 스트리밍 복사(대용량 파일 대비)
                with open(output_target, 'wb') as outfile:
                    chunk = file_object.read(1024 * 1024)
                    while chunk: outfile.write(chunk); chunk = file_object.read(1024 * 1024)
                file_object.close()
            log_result(collected_paths, category_key, "SUCCESS", original_full_path)
        except Exception as e: log_result(collected_paths, category_key, "FAILED", original_full_path, error_msg=f"Failed to write file: {e}")
    elif entry.IsDirectory():
        output_target.mkdir(parents=True, exist_ok=True)
        log_result(collected_paths, category_key, "SUCCESS", original_full_path)
        try:
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], artifact_info, collected_paths)
        except Exception as e: log_result(collected_paths, category_key, "FAILED", f"{original_full_path}/{sub_entry.name}", error_msg=f"Failed to process subdirectory item: {e}")

def final_summary(collected_paths, program_output_dir, path_log_file_path, verbose=False, keep_plus=True):
    # 최종 요약 출력
    #     - verbose 모드일 때 카테고리별 테이블을 보여주고
    #     - 항상 결과 경로 및 로그 파일 경로를 안내.
    if verbose:
        console.print()
        table = Table(title=Align.center("Artifact Extraction Summary"), show_header=True, header_style="bold", box=HEAVY_HEAD)
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Extracted", justify="right")
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
    console.print("\n[*] Processing complete.")
    console.print(f"    - Extracted files are in: [cyan]{program_output_dir.resolve()}[/cyan]")
    console.print(f"    - See the full report at: [cyan]{path_log_file_path.resolve()}[/cyan]")

def write_extracted_paths_log(collected_paths, program_output_dir, image_name, image_hash, llm_name, mode, tool_version, command_line, execution_time, keep_plus=True):
    # 상세 로그 파일(extraction_report.txt) 작성
    #  - 실행 컨텍스트(해시/버전/명령줄/타임스탬프)와 카테고리별 성공/실패, 총 소요시간 등을 기록.
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
    # 명령줄 인자 파서 정의
    #     - MODE: api | standalone
    #     - LLM_NAME: 정의된 이름 또는 임의 문자열(휴리스틱 모드)
    #     - 옵션: -c(color), -v(verbose), -p('+'→'_' 치환), -s(최종요약 비활성)
    parser = argparse.ArgumentParser(
        description="extract_llm: Extracts forensic artifacts of LLM applications from an E01 image.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result -c\n  python %(prog)s ./E01/CLAUDE.E01 api CLAUDE ./result -v"
    )
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed.")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode.")
    parser.add_argument("LLM_NAME", help="Name of the LLM program to extract artifacts from.")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved.")
    parser.add_argument("-c", "--color", action="store_true", help="Enable colorized output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (implies color).")
    parser.add_argument("-p", "--no-keep-plus", action="store_true", help="Replace '+' with '_' in category folder names.")
    parser.add_argument("-s", "--no-final-summary", action="store_true", help="Disable the final summary message.")
    return parser.parse_args()

def main():
    # 진입점: 인자 파싱 → 콘솔 초기화 → E01 유효성 검사 → 아티팩트 정의 로드 → 파티션/루트 탐색 → 재귀 추출 → 로그/요약 출력
    global console
    start_time = time.time()
    args = parse_args()
    
    # verbose 모드이면 색상 출력 자동 활성화
    use_color = args.color or args.verbose
    console = Console(no_color=not use_color)
    
    if IS_MOCK_MODE: console.print("[!] [yellow]Warning[/yellow]: Running in Mock Mode.")

    e01_image_path = Path(args.E01_IMAGE_PATH)
    if not e01_image_path.is_file() and not IS_MOCK_MODE:
        console.print(f"\n[!] [red]Error[/red]: The specified E01 image file does not exist: {e01_image_path.resolve()}"); sys.exit(1)

    llm_name_upper = args.LLM_NAME.upper()
    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        header_panel(args.E01_IMAGE_PATH, llm_name_upper, args.MODE, str(program_output_dir.resolve()))
    else:
        console.print(f"[*] Processing: [bold cyan]{args.E01_IMAGE_PATH}[/bold cyan] for [bold cyan]{llm_name_upper}[/bold cyan] artifacts...")
    
    # E01 이미지 SHA-256 계산(목 모드일 경우 N/A)
    image_hash = "N/A (Mock Mode)" if IS_MOCK_MODE else calculate_sha256(e01_image_path)
    
    # LLM 이름이 사전 정의되었는지 확인. 아니면 휴리스틱 모드로 전환.
    is_defined_llm = llm_name_upper in LLM_ARTIFACTS
    is_heuristic_mode = not is_defined_llm
    if is_heuristic_mode:
        heuristic_key = f"_HEURISTICS_{args.MODE.upper()}"
        if heuristic_key not in LLM_ARTIFACTS:
            console.print(f"\n[!] [red]Error[/red]: Heuristic definition '{heuristic_key}' not found for '{args.LLM_NAME}'."); sys.exit(1)
        artifacts_to_extract = LLM_ARTIFACTS[heuristic_key]
        console.print("[!] [yellow]Warning[/yellow]: Running in Heuristic Discovery Mode.")
    else: artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    
    # 이미지에서 Windows가 존재하는 NTFS 파티션을 찾아 루트 엔트리를 획득
    root_entry, _ = get_image_root_entry(e01_image_path)
    if root_entry is None: sys.exit(1)

    # 카테고리별 수집 결과를 담는 구조체(dict of list)
    collected_paths = {}
    # 진행률 표시(스피너 + 바). verbose 여부에 따라 설명 문구만 달라짐.
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), console=console, transient=True) as progress:
        task_description = "[cyan]Processing categories...[/cyan]" if args.verbose else "[cyan]Processing artifacts...[/cyan]"
        task = progress.add_task(task_description, total=len(artifacts_to_extract))
        for category, artifacts in artifacts_to_extract.items():
            if args.verbose: progress.update(task, description=f"[cyan]Processing: {category.replace('_', ' ')}...[/cyan]")
            # 옵션에 따라 카테고리 이름의 '+'를 '_'로 치환하여 출력/폴더 구성
            category_key = category if not args.no_keep_plus else category.replace('+', '_')
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                if is_heuristic_mode:
                    # 휴리스틱 모드에서는 경로 내 {LLM_NAME} 플레이스홀더를 실제 입력값으로 치환
                    full_path = full_path.replace("{LLM_NAME}", llm_name_upper)
                    artifact_info["llm_name_placeholder"] = llm_name_upper
                # 경로 정규화 후 토큰 분리하여 재귀 탐색 실행
                recursive_search_and_extract(root_entry, normalize_path(full_path).split('/'), program_output_dir, Path(category_key), [], artifact_info, collected_paths)
            if IS_MOCK_MODE: time.sleep(0.5)
            progress.update(task, advance=1)
            
    # verbose 모드에서는 카테고리별 성공/실패 요약 알림을 별도로 출력
    if args.verbose:
        console.print("\n[*] Extraction process finished. Finalizing results...")
        for category_key, results in sorted(collected_paths.items()):
            succeeded = sum(1 for r in results if r['status'] == 'SUCCESS')
            failed = len(results) - succeeded
            label = category_key.replace('_', ' ')
            if failed > 0: console.print(f"[!] [red]ALERT[/red]: {label}: {succeeded} extracted, {failed} failed")
            else: console.print(f"[*] [green]INFO[/green]:  {label}: {succeeded} extracted, 0 failed")

    # 실행 시간 계산 및 상세 로그 파일 작성
    execution_time = time.time() - start_time
    path_log_file_path = write_extracted_paths_log(collected_paths, program_output_dir, e01_image_path.name, image_hash, llm_name_upper, args.MODE, __version__, sys.argv, execution_time, not args.no_keep_plus)
    
    # -s/--no-final-summary 옵션이 아니면 최종 요약 출력
    if not args.no_final_summary:
        final_summary(collected_paths, program_output_dir, path_log_file_path, verbose=args.verbose, keep_plus=not args.no_keep_plus)

if __name__ == "__main__":
    # 스크립트 직접 실행 시 main() 진입
    main()
