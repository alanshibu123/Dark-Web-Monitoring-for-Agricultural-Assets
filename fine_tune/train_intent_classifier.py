#!/usr/bin/env python3
"""
Fine-tune BART for Dark Web Agriculture Intent Classification
"""

import json
import os
import numpy as np
from sklearn.model_selection import train_test_split
from datasets import Dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback
)
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

# ============================================
# CONFIGURATION
# ============================================

MODEL_NAME = "facebook/bart-base"
MAX_LENGTH = 256
BATCH_SIZE = 4
EPOCHS = 5
LEARNING_RATE = 2e-5
TRAIN_RATIO = 0.8

# Intent categories
INTENT_CATEGORIES = [
    "credential_dump",
    "data_breach_announcement", 
    "proprietary_data_sale",
    "agriculture_research",
    "ransomware_threat",
    "marketplace_listing",
    "technical_discussion",
    "false_positive_sample"
]

# Create label mappings
label2id = {label: i for i, label in enumerate(INTENT_CATEGORIES)}
id2label = {i: label for label, i in label2id.items()}

print("="*60)
print("BART FINE-TUNING FOR DARK WEB CLASSIFICATION")
print("="*60)
print(f"Model: {MODEL_NAME}")
print(f"Categories: {len(INTENT_CATEGORIES)}")
print(f"Label mapping: {label2id}")
print("="*60)

# ============================================
# LOAD AND PREPARE DATA
# ============================================

def load_training_data(json_path: str = "data/premade_training_data.json"):
    """Load training data from JSON file"""
    
    if not os.path.exists(json_path):
        print(f"\n❌ File not found: {json_path}")
        print("Please create the training data file first.")
        return None
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    print(f"\n✅ Loaded {len(data)} examples from {json_path}")
    
    # Count examples per intent
    counts = {}
    for item in data:
        intent = item["intent"]
        counts[intent] = counts.get(intent, 0) + 1
    
    print("\n📊 Dataset distribution:")
    for intent, count in counts.items():
        print(f"  {intent}: {count} examples")
    
    return data

def prepare_dataset(data):
    """Convert data to Hugging Face Dataset format"""
    
    texts = [item["text"] for item in data]
    labels = [label2id[item["intent"]] for item in data]
    
    # Split into train and validation
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, 
        train_size=TRAIN_RATIO, 
        random_state=42,
        stratify=labels
    )
    
    print(f"\n📁 Split data:")
    print(f"  Train: {len(train_texts)} examples")
    print(f"  Validation: {len(val_texts)} examples")
    
    # Create datasets
    train_dataset = Dataset.from_dict({
        "text": train_texts,
        "label": train_labels
    })
    
    val_dataset = Dataset.from_dict({
        "text": val_texts,
        "label": val_labels
    })
    
    return DatasetDict({
        "train": train_dataset,
        "validation": val_dataset
    })

# ============================================
# TOKENIZATION
# ============================================

def tokenize_dataset(datasets, tokenizer):
    """Tokenize the dataset"""
    
    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=MAX_LENGTH
        )
    
    print("\n🔤 Tokenizing dataset...")
    tokenized_datasets = datasets.map(tokenize_function, batched=True)
    
    # Remove text column
    tokenized_datasets = tokenized_datasets.remove_columns(["text"])
    
    return tokenized_datasets

# ============================================
# METRICS FUNCTION
# ============================================

def compute_metrics(eval_pred):
    """Calculate evaluation metrics"""
    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)
    
    accuracy = accuracy_score(labels, predictions)
    f1 = f1_score(labels, predictions, average="weighted")
    precision, recall, _, _ = precision_recall_fscore_support(
        labels, predictions, average="weighted"
    )
    
    return {
        "accuracy": accuracy,
        "f1": f1,
        "precision": precision,
        "recall": recall
    }

# ============================================
# MAIN TRAINING FUNCTION
# ============================================

def main():
    """Main training function"""
    
    # 1. Load data
    data = load_training_data()
    if not data:
        return
    
    # 2. Prepare dataset
    datasets = prepare_dataset(data)
    
    # 3. Load tokenizer
    print(f"\n📥 Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    # 4. Tokenize
    tokenized_datasets = tokenize_dataset(datasets, tokenizer)
    
    # 5. Load model
    print(f"\n📥 Loading model: {MODEL_NAME}")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(INTENT_CATEGORIES),
        id2label=id2label,
        label2id=label2id,
        ignore_mismatched_sizes=True
    )
    
    # 6. Training arguments
    training_args = TrainingArguments(
        output_dir="./intent_model_results",
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_dir="./logs",
        logging_steps=10,
        save_total_limit=2,
        fp16=False,
        report_to="none"
    )
    
    # 7. Initialize trainer (FIXED: removed tokenizer parameter)
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["validation"],
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
    )
    
    # 8. Train
    print("\n" + "="*60)
    print("🚀 STARTING TRAINING...")
    print("="*60)
    
    trainer.train()
    
    # 9. Save model
    print("\n💾 Saving fine-tuned model...")
    model.save_pretrained("./intent_model_final")
    tokenizer.save_pretrained("./intent_model_final")
    
    # 10. Final evaluation
    print("\n📊 Final Evaluation:")
    eval_results = trainer.evaluate()
    for key, value in eval_results.items():
        print(f"  {key}: {value:.4f}")
    
    print("\n✅ Training complete!")
    print(f"Model saved to: ./intent_model_final")
    
    # 11. Test on samples
    print("\n🧪 Testing on sample texts:")
    test_samples = [
        ("AgriFarm database leaked: admin:Harvest2024", "credential_dump"),
        ("Selling access to CropMonitor API. $500.", "marketplace_listing"),
        ("This is a sample for testing only.", "false_positive_sample"),
        ("How to configure PostgreSQL for farm data?", "technical_discussion"),
        ("Your irrigation system has been encrypted. Pay 20 BTC.", "ransomware_threat"),
        ("Ministry of Agriculture servers breached.", "data_breach_announcement"),
    ]
    
    model.eval()
    for text, expected in test_samples:
        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=MAX_LENGTH)
        with torch.no_grad():
            outputs = model(**inputs)
        prediction = np.argmax(outputs.logits.detach().numpy(), axis=1)[0]
        predicted_label = id2label[prediction]
        status = "✅" if predicted_label == expected else "⚠️"
        print(f"  {status} Expected: {expected}, Got: {predicted_label}")
        print(f"     Text: {text[:60]}...")
    
    return True

if __name__ == "__main__":
    import torch  # Add this import
    main()