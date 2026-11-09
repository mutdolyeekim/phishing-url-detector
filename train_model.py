"""Train an educational phishing URL classifier using a CSV with url,label."""
from pathlib import Path
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DATA_PATH = Path(__file__).resolve().parent / "phishing-dataset" / "urls.csv"
MODEL_PATH = Path(__file__).resolve().parent / "phishing_url_model.joblib"


def main():
    if not DATA_PATH.exists():
        raise SystemExit(
            f"데이터 파일이 없습니다: {DATA_PATH}\n"
            "'url'과 'label' 컬럼이 있는 CSV 파일을 urls.csv로 저장하세요. "
            "label: 0=정상, 1=피싱"
        )

    df = pd.read_csv(DATA_PATH, low_memory=False)
    df.columns = df.columns.str.strip().str.lower()
    required = {"url", "label"}
    if not required.issubset(df.columns):
        raise SystemExit(
            "데이터 컬럼이 맞지 않습니다. 현재 컬럼: "
            + ", ".join(df.columns)
            + "\n필요한 컬럼: url, label (0=정상, 1=피싱)"
        )

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[(df["url"] != "") & df["label"].isin([0, 1])]
    # Duplicate URLs shared between training and testing distort measured accuracy.
    df = df.drop_duplicates(subset=["url"], keep="first")
    if df["label"].nunique() != 2 or len(df) < 20:
        raise SystemExit("정상(0)과 피싱(1) 데이터를 각각 충분히 포함해야 합니다.")

    print(f"학습용 URL 수: {len(df):,}")
    print("레이블 분포:", df["label"].value_counts().to_dict())
    X_train, X_test, y_train, y_test = train_test_split(
        df["url"], df["label"].astype(int),
        test_size=0.2, random_state=42, stratify=df["label"]
    )

    clf = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5),
            min_df=2, max_features=100_000, lowercase=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=42
        )),
    ])
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("\n분류 평가 (0=정상, 1=피싱):")
    print(classification_report(
        y_test, y_pred, labels=[0, 1],
        target_names=["정상", "피싱"], digits=4, zero_division=0
    ))
    print("혼동 행렬 [[정상→정상, 정상→피싱], [피싱→정상, 피싱→피싱]]:")
    print(confusion_matrix(y_test, y_pred, labels=[0, 1]))
    joblib.dump(clf, MODEL_PATH)
    print(f"\n모델 저장 완료: {MODEL_PATH}")


if __name__ == "__main__":
    main()
