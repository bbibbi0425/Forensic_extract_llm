# extract_llm – LLM 포렌식 아티팩트 추출용 자동화 스크립트

E01 디스크 이미지에서 **LLM 애플리케이션(ChatGPT, Claude, LM Studio, Jan, 미정의 LLM 등**의
**실행 흔적 / 사용자 정보 / 프롬프트 / 파일 업로드 / 네트워크 아티팩트**를 자동으로 수집하여
결과 폴더로 정리합니다. 

dfVFS를 통해 E01 이미지를 읽고, 앱별 **경로 패턴(artifacts.json)** 또는
**휴리스틱 패턴**을 재귀적으로 탐색합니다.

---

## 주요 특징(Features)

- **세 가지 콘솔 출력 모드**
  - 기본(default): 핵심 진행 메시지만 간결히 표시
  - 컬러(-c): 컬러 하이라이트 적용
  - 자세히(-v): 헤더/카테고리 요약/최종 테이블 등 상세 정보 복원
- **포렌식 로깅**
  - 소스 이미지 **SHA‑256**, 도구 버전, 실행 컨텍스트, 성공/실패 카운트, 소요 시간 포함
  - `extraction_report.txt` 파일로 상세 경로/에러 로그 기록
- **휴리스틱 모드 지원**
  - 정의되지 않은 LLM 이름을 입력해도 모드(`api`/`standalone`)에 맞춘 기본 경로 패턴으로 탐색
- **카테고리 기반 수집**
  - `Program_Execution_Traces`, `User_Info`, `Prompt(+File_Uploads)`, `Network` 등 카테고리별 폴더 구성

> 세부 경로 패턴은 **`artifacts.json`**을 참고하세요.

---

## 지원 대상
- **MODE = api**: `CHATGPT`, `CLAUDE`
- **MODE = standalone**: `LMSTUDIO`, `JAN`
- **그 외 LLM**: 위 2가지 모드 중 하나를 선택하여 **휴리스틱 모드**로 수집 가능

---

## 요구 사항(Requirements)

- **Python**: 3.9 이상
- **필수 패키지**: `dfvfs`, `pytsk3`, `libewf-python`, `rich`
- **네이티브 라이브러리**
  - **Ubuntu/WSL**: `libtsk-dev`, `libewf-dev`, `libbde-dev`, `libfsntfs-dev`, `build-essential`, `python3-dev`
  - **Windows**: WSL(우분투) 사용 권장
  - **macOS(Homebrew)**: `sleuthkit`, `libewf`, `pkg-config`

---

## 설치 및 실행(Quick Start)

### 1) 리포지토리 클론
```bash
git clone https://github.com/forensicbread/WHS_tool.git
cd WHS_tool
```

### 2) Windows(WSL‑Ubuntu) – 방법 A: 자동 설치 스크립트
```powershell
# PowerShell(관리자)
wsl --install -d Ubuntu
# 재부팅 후 WSL(“Ubuntu”) 실행

# (WSL) 리포지토리로 이동
cd "<YOUR_PATH_TO_WHS_tool>"

# (WSL) 스크립트 권한 및 실행
chmod +x setup_wsl.sh
sed -i 's/\r$//' setup_wsl.sh && bash ./setup_wsl.sh

# (WSL) 가상환경 활성화
source ~/venvs/whs-windows/bin/activate

# (WSL) 실행 예시
python -m extract_llm ./E01/CLAUDE.E01 api CLAUDE ./result
# 또는 상세 모드
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

### 3) Windows(WSL‑Ubuntu) – 방법 B: 수동 설치
```bash
# (WSL) 네이티브 라이브러리 설치
sudo apt update
sudo apt install -y   python3-venv python3-dev build-essential   libtsk-dev libewf-dev libbde-dev libfsntfs-dev

# (WSL) 가상환경 생성/활성화
mkdir -p ~/venvs
python3 -m venv --prompt whs-windows ~/venvs/whs-windows
source ~/venvs/whs-windows/bin/activate

# (WSL) 파이썬 의존성
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# (WSL) 실행 예시
python -m extract_llm ./E01/CLAUDE.E01 api CLAUDE ./result
# 또는 상세 모드
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

### 4) macOS: 자동 설치 스크립트
```bash
cd "<YOUR_PATH_TO_WHS_tool>"
chmod +x setup_macos.sh
./setup_macos.sh

# 설치 완료 후
source .venv-macos/bin/activate

# 실행 예시
python -m extract_llm ./E01/CLAUDE.E01 api CLAUDE ./result
# 또는 상세 모드
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

---

## 명령줄 사용법(Usage)

```bash
python extract_llm.py <E01_IMAGE> <MODE> <LLM_NAME> <OUTPUT_DIR> [옵션]
```

- `MODE`: `api` | `standalone`
- `LLM_NAME`: `CHATGPT` | `CLAUDE` | `LMSTUDIO` | `JAN` | *(그 외 문자열은 휴리스틱 모드)*
- `OUTPUT_DIR`: 결과 저장 폴더(없으면 자동 생성)

### 옵션(Flags)
- `-c, --color` : 컬러 출력 활성화
- `-v, --verbose` : **상세 모드** 활성화(헤더/요약/테이블 표시, 암묵적으로 `--color` 포함)
- `-p, --no-keep-plus` : 카테고리 폴더명에서 `+`를 `_`로 치환
- `-s, --no-final-summary` : 마지막 **요약 메시지** 출력 생략

> 과거 문서의 `--no-show-summary` 옵션은 제거되었으며, 현재는 `-s/--no-final-summary`로 통일되었습니다.

#### 예시(Examples)
```bash
# 최소 출력
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result

# 컬러 활성화
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result -c

# 상세 모드(헤더/요약/테이블)
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result -v

# 카테고리명에서 '+'를 '_'로 치환
python extract_llm.py ./E01/LMSTUDIO.E01 standalone LMSTUDIO ./result -p
```

---

## 결과물(Output)

- `./result/<LLM_NAME>/<카테고리>/...` : 추출된 파일/디렉터리
- `./result/<LLM_NAME>/extraction_report.txt` : 실행 컨텍스트 + **상세 경로/에러 로그**
  - 이미지 파일명/경로, **SHA‑256**, LLM 타깃/모드, 명령줄, 타임스탬프
  - 카테고리별 성공/실패 카운트, 전체 소요 시간

### 요약 테이블(Verbose 모드)
상세 모드(`-v`)에서 카테고리별 **추출/실패 카운트 테이블** 및 최종 요약 메시지를 화면에 표시합니다.

---

## 동작 개요(How it works)

1. **이미지 파티션 탐색**: `/p1`…`/p10`에서 NTFS + `Windows` 폴더 존재 파티션 자동 탐지
2. **경로 정규화/와일드카드 매칭**: `\`→`/` 변환, 대소문자 무시, `*` 패턴 처리
3. **카테고리별 재귀 수집**: `Program_Execution_Traces`, `User_Info`, `Prompt(+File_Uploads)`, `Network` 등
4. **부분 추출**: 필요 시 `extract_files` 키(`Cookies`, `Network Persistent State` 등)만 선별 추출
5. **로그/요약 출력**: 성공/실패 분리 기록 및 `extraction_report.txt` 저장


---

