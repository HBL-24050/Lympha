from __future__ import annotations

import csv
import logging
import numpy as np

from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from peft import LoraConfig, get_peft_model, TaskType

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("finetune")

DATASET_PATH = "data/output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv"
MODEL_NAME = "microsoft/codebert-base"
OUTPUT_DIR = "models/tier2/codebert-finetuned"
MAX_LENGTH = 128
BATCH_SIZE = 8
EPOCHS = 3
LEARNING_RATE = 3e-4
TEST_SPLIT = 0.1
MAX_SAMPLES = 5000


def load_csic2010(path: str, max_samples: int = MAX_SAMPLES) -> list[dict]:
    requests: dict[str, dict] = {}

    with open(path) as f:
        reader = csv.reader(f)
        next(reader)

        for row in reader:
            idx = row[0]
            if idx not in requests:
                requests[idx] = {
                    "method": row[1],
                    "url": row[2],
                    "payloads": [],
                    "label": row[-1],
                }
            payload = row[16]
            if payload and payload != "null":
                requests[idx]["payloads"].append(payload)

    result = []
    for req in requests.values():
        method = req["method"]
        url = req["url"]
        payload_str = "&".join(req["payloads"]) if req["payloads"] else ""
        text = f"{method} {url}?{payload_str}" if payload_str else f"{method} {url}"
        label = 1 if req["label"] == "anom" else 0
        result.append({"text": text, "label": label})

    np.random.shuffle(result)
    return result[:max_samples]


def tokenize_fn(batch, tokenizer):
    return tokenizer(
        batch["text"],
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
    )


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    acc = (preds == labels).mean()
    tp = ((preds == 1) & (labels == 1)).sum()
    fp = ((preds == 1) & (labels == 0)).sum()
    fn = ((preds == 0) & (labels == 1)).sum()
    prec = tp / (tp + fp + 1e-8)
    rec = tp / (tp + fn + 1e-8)
    f1 = 2 * prec * rec / (prec + rec + 1e-8)
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}


def main():
    log.info("Loading CSIC 2010 dataset...")
    data = load_csic2010(DATASET_PATH)
    log.info("Loaded %d samples (%d attack, %d benign)",
             len(data), sum(1 for d in data if d["label"] == 1),
             sum(1 for d in data if d["label"] == 0))

    split = int(len(data) * TEST_SPLIT)
    train_data = data[split:]
    test_data = data[:split]

    train_ds = Dataset.from_list(train_data)
    test_ds = Dataset.from_list(test_data)

    log.info("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    log.info("Loading model + LoRA...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2,
    )

    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        lora_dropout=0.1,
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    train_ds = train_ds.map(lambda b: tokenize_fn(b, tokenizer), batched=True)
    test_ds = test_ds.map(lambda b: tokenize_fn(b, tokenizer), batched=True)

    train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
    test_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

    args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        remove_unused_columns=False,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=test_ds,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    log.info("Starting training...")
    trainer.train()

    log.info("Saving model to %s", OUTPUT_DIR)
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    log.info("Final evaluation:")
    metrics = trainer.evaluate(test_ds)
    for k, v in metrics.items():
        log.info("  %s = %.4f", k, v)


if __name__ == "__main__":
    main()
