# URL Guardian AI (피싱 URL 검사기)

한국어 Streamlit 웹앱으로 URL 문자열의 패턴을 머신러닝으로 분류하는 **교육용** 프로젝트입니다. 방문하거나 실제 사이트 내용을 검사하지 않습니다.

## 1. 데이터 준비

`phishing-dataset/urls.csv`를 준비합니다. 헤더가 정확히 다음처럼 있어야 합니다.

```
url,label
https://example.com,0
https://some-other-example.invalid/login,1
```

위 두 줄은 **형식을 설명하기 위한 예시**이며 실제 사이트의 안전/위험을 판단한 레이블이 아닙니다. 학습용으로 사용하지 마세요.

사용할 수 있는 공개 데이터: [URL-Phish (Mendeley Data)](https://data.mendeley.com/datasets/65z9twcx3r/2). 이 데이터의 `url`과 `label` 컬럼이 있으며 `0=정상`, `1=피싱`으로 안내되어 있습니다. CSV 파일을 내려받아 이름을 `urls.csv`로 바꿔 폴더에 두세요. 다른 컬럼은 있어도 무방하며 학습에서는 무시합니다. 라이선스와 출처를 확인하세요.

**중요:** 기존 `train.csv`/`test.csv`에 URL 문자열 열이 없고 수치형 특징만 있다면 그 데이터를 이 앱에 그대로 사용하면 안 됩니다. 텍스트 URL에 맞는 학습 데이터가 따로 필요합니다.

## 2. VS Code 터미널에서 실행

프로젝트 폴더를 연 후 다음을 순서대로 실행하세요.

```powershell
python -m pip install -r requirements.txt
python train_model.py
python -m streamlit run app.py
```

터미널에 표시되는 로컬 주소(보통 `http://localhost:8501`)를 브라우저에서 엽니다.

## 3. 파일 설명

- `train_model.py`: URL 학습 CSV로 문자 n-gram TF-IDF + 로지스틱 회귀 모델 학습, 평가 및 저장
- `app.py`: 한국어 Streamlit 입력창과 검사 결과 표시
- `requirements.txt`: 필요 라이브러리
- `phishing-dataset/urls.csv`: 사용자가 별도로 내려받을 데이터 (압축 파일에는 포함하지 않음)
- `phishing_url_model.joblib`: 학습 이후 자동 생성되는 모델 파일

## 4. 나중에 배포하기

로컬에서 모델을 학습한 후 `app.py`, `requirements.txt`, 직접 생성한 `phishing_url_model.joblib` 파일을 GitHub 저장소에 올리고 [Streamlit Community Cloud](https://share.streamlit.io/)에서 `app.py`를 지정하여 배포할 수 있습니다. `phishing-dataset`의 원본 피싱 URL은 굳이 공개할 필요가 없습니다. 공개 배포 전 데이터 라이선스를 확인하고, 출처가 불확실한 외부 `.joblib` 파일은 절대 로드하지 마세요.

## 주의

- 결과는 실제 악성 사이트 여부를 확정하지 않습니다. '낮음'도 접속 안전을 의미하지 않습니다.
- 표시되는 점수는 보정되지 않은 모델 분류 점수로, 실제 위험 확률과 같지 않습니다.
- 입력 URL에 비밀번호/토큰/민감정보가 있으면 입력하지 마세요.
- 학습 데이터 중복, 오래된 데이터, 분포 차이, 레이블 오류 때문에 성능이 과장될 수 있습니다.
