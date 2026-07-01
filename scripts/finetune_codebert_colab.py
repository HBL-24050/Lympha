# --- Cell 1: Install deps ---
# Run this in Google Colab (Runtime → Change runtime type → T4 GPU)
# !pip install transformers datasets peft accelerate pandas

# --- Cell 2: Download CSIC 2010 dataset ---
import os, csv, numpy as np
from pathlib import Path

DATASET_URL = "http://lexr.ai/csic_dataset/output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv.zip"

Path("data").mkdir(exist_ok=True)
if not Path("data/csic2010.csv").exists():
    !wget -q {DATASET_URL} -O data/csic2010.zip
    !unzip -q -o data/csic2010.zip -d data/
    csv_files = list(Path("data").glob("*.csv"))
    if csv_files:
        csv_files[0].rename("data/csic2010.csv")

# --- Cell 3: Load and prepare dataset ---
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer, EarlyStoppingCallback
from peft import LoraConfig, get_peft_model, TaskType

def load_csic2010(path, max_samples=20000):
    requests = {}
    with open(path) as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            idx = row[0]
            if idx not in requests:
                requests[idx] = {"method": row[1], "url": row[2], "payloads": [], "label": row[-1]}
            payload = row[16]
            if payload and payload != "null":
                requests[idx]["payloads"].append(payload)

    result = []
    for req in list(requests.values())[:max_samples]:
        method = req["method"]
        url = req["url"]
        payload_str = "&".join(req["payloads"]) if req["payloads"] else ""
        text = f"{method} {url}?{payload_str}" if payload_str else f"{method} {url}"
        label = 1 if req["label"] == "anom" else 0
        result.append({"text": text, "label": label})
    np.random.shuffle(result)
    return result

data = load_csic2010("data/csic2010.csv", max_samples=20000)
split = int(len(data) * 0.1)
train_ds = Dataset.from_list(data[split:])
test_ds = Dataset.from_list(data[:split])
print(f"Train: {len(train_ds)}, Test: {len(test_ds)}")

# --- Cell 4: Load CodeBERT + LoRA ---
MODEL_NAME = "microsoft/codebert-base"
OUTPUT_DIR = "/content/codebert-finetuned"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
lora_config = LoraConfig(task_type=TaskType.SEQ_CLS, r=8, lora_alpha=16, lora_dropout=0.1, bias="none")
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

def tokenize(batch):
    return tokenizer(batch["text"], padding="max_length", truncation=True, max_length=128)

train_ds = train_ds.map(tokenize, batched=True)
test_ds = test_ds.map(tokenize, batched=True)
train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
test_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

# --- Cell 5: Train ---
args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    eval_strategy="epoch",
    save_strategy="epoch",
    save_total_limit=2,
    learning_rate=3e-4,
    per_device_train_batch_size=32,
    per_device_eval_batch_size=32,
    num_train_epochs=3,
    weight_decay=0.01,
    logging_steps=50,
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True,
    remove_unused_columns=False,
    fp16=True,                   # use GPU half-precision
    dataloader_pin_memory=False,
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

trainer = Trainer(
    model=model, args=args,
    train_dataset=train_ds, eval_dataset=test_ds,
    compute_metrics=compute_metrics,
    callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
)

trainer.train()

# --- Cell 6: Save + download ---
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print(f"Model saved to {OUTPUT_DIR}")

# Zip for download
!zip -r /content/codebert-finetuned.zip {OUTPUT_DIR}
from google.colab import files
files.download("/content/codebert-finetuned.zip")
