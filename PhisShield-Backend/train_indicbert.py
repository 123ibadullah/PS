from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "Phishing_Email.csv"
OUTPUT_DIR = BASE_DIR / "indicbert_model"
METADATA_PATH = BASE_DIR / "training_meta.json"
MODEL_NAME = "ai4bharat/indic-bert"
MODEL_CANDIDATES = [MODEL_NAME, "ai4bharat/IndicBERTv2-MLM-only"]
LABEL_MAP = {
    "Safe Email": 0,
    "Phishing Email": 1,
}
ID2LABEL = {0: "Safe Email", 1: "Phishing Email"}
LABEL2ID = {label: idx for idx, label in ID2LABEL.items()}
MAX_LENGTH = 128
CPU_SAMPLE_LIMIT = 640

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


def load_dataset_frame() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)
    expected_columns = {"Email Text", "Email Type"}
    missing_columns = expected_columns.difference(df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns: {sorted(missing_columns)}")

    df = df[["Email Text", "Email Type"]].dropna().copy()
    df["label"] = df["Email Type"].map(LABEL_MAP)

    if df["label"].isna().any():
        unknown = sorted(df.loc[df["label"].isna(), "Email Type"].astype(str).unique().tolist())
        raise ValueError(f"Unsupported label values found: {unknown}")

    df["text"] = df["Email Text"].astype(str).str.strip()
    df = df[df["text"].astype(bool)].copy()
    df["label"] = df["label"].astype(int)
    return df[["text", "label"]]


def load_pretrained_assets() -> tuple[str, AutoTokenizer, AutoModelForSequenceClassification]:
    last_error: Exception | None = None
    for candidate in MODEL_CANDIDATES:
        try:
            tokenizer = AutoTokenizer.from_pretrained(candidate, use_fast=False)
            model = AutoModelForSequenceClassification.from_pretrained(
                candidate,
                num_labels=2,
                id2label=ID2LABEL,
                label2id=LABEL2ID,
                ignore_mismatched_sizes=True,
            )
            return candidate, tokenizer, model
        except Exception as exc:  # pragma: no cover - depends on remote model availability
            last_error = exc
    raise RuntimeError(f"Unable to load IndicBERT from {MODEL_CANDIDATES}: {last_error}")


def compute_metrics(eval_prediction: tuple[object, object]) -> dict[str, float]:
    logits, labels = eval_prediction
    predictions = logits.argmax(axis=-1)
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
    }


def apply_cpu_friendly_finetuning(model: AutoModelForSequenceClassification) -> None:
    base_model = getattr(model, "bert", None) or getattr(model, "base_model", None)
    if base_model is None:
        return

    for param in base_model.parameters():
        param.requires_grad = False

    encoder = getattr(base_model, "encoder", None)
    layers = getattr(encoder, "layer", None)
    if layers:
        for layer in layers[-1:]:
            for param in layer.parameters():
                param.requires_grad = True

    pooler = getattr(base_model, "pooler", None)
    if pooler is not None:
        for param in pooler.parameters():
            param.requires_grad = True

    for param in model.classifier.parameters():
        param.requires_grad = True


def main() -> None:
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")

    df = load_dataset_frame()
    full_row_count = len(df)
    if device == "cpu" and len(df) > CPU_SAMPLE_LIMIT:
        per_class = CPU_SAMPLE_LIMIT // 2
        safe_subset = df[df["label"] == 0].sample(n=per_class, random_state=42)
        phish_subset = df[df["label"] == 1].sample(n=per_class, random_state=42)
        df = pd.concat([safe_subset, phish_subset], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"CPU mode detected — using a balanced {len(df):,}/{full_row_count:,} row subset for practical 3-epoch fine-tuning.")

    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    model_name_used, tokenizer, model = load_pretrained_assets()
    if device == "cpu":
        apply_cpu_friendly_finetuning(model)
    print(f"Loaded pretrained model: {model_name_used}")

    train_dataset = Dataset.from_pandas(train_df.reset_index(drop=True))
    test_dataset = Dataset.from_pandas(test_df.reset_index(drop=True))

    def tokenize(batch: dict[str, list[str]]) -> dict[str, object]:
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH)

    train_dataset = train_dataset.map(tokenize, batched=True, remove_columns=["text"])
    test_dataset = test_dataset.map(tokenize, batched=True, remove_columns=["text"])

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR / "checkpoints"),
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        learning_rate=2e-5,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to=[],
        fp16=device == "cuda",
        use_cpu=device == "cpu",
        dataloader_num_workers=0,
        seed=42,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    summary_metrics = {
        "accuracy": float(metrics.get("eval_accuracy", 0.0)),
        "precision": float(metrics.get("eval_precision", 0.0)),
        "recall": float(metrics.get("eval_recall", 0.0)),
        "f1": float(metrics.get("eval_f1", 0.0)),
    }

    training_metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(DATASET_PATH),
        "rows": int(len(df)),
        "source_rows": int(full_row_count),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "model_type": "IndicBERT",
        "pretrained_model": model_name_used,
        "device": device,
        "metrics": summary_metrics,
    }
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(training_metadata, indent=2), encoding="utf-8")
    METADATA_PATH.write_text(json.dumps(training_metadata, indent=2), encoding="utf-8")

    print("=== IndicBERT Fine-Tuning Complete ===")
    print(f"Dataset rows: {len(df):,}")
    print(f"Training rows: {len(train_df):,}")
    print(f"Testing rows: {len(test_df):,}")
    print(f"Accuracy : {summary_metrics['accuracy']:.4f}")
    print(f"Precision: {summary_metrics['precision']:.4f}")
    print(f"Recall   : {summary_metrics['recall']:.4f}")
    print(f"F1 Score : {summary_metrics['f1']:.4f}")
    print(f"Saved IndicBERT model to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
