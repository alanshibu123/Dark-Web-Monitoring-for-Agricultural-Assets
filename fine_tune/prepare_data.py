from datasets import Dataset, DatasetDict
from transformers import AutoTokenizer
import json

# Load your training data
with open("data/training_data.json", "r") as f:
    data = json.load(f)

# Split into train/validation (80/20 split)
random.shuffle(data)
split_idx = int(len(data) * 0.8)
train_data = data[:split_idx]
val_data = data[split_idx:]

# Create label mapping
labels = INTENT_CATEGORIES
label2id = {label: i for i, label in enumerate(labels)}
id2label = {i: label for label, i in label2id.items()}

# Convert to Hugging Face Dataset
train_dataset = Dataset.from_list([
    {"text": item["text"], "label": label2id[item["intent"]]}
    for item in train_data
])

val_dataset = Dataset.from_list([
    {"text": item["text"], "label": label2id[item["intent"]]}
    for item in val_data
])

datasets = DatasetDict({
    "train": train_dataset,
    "validation": val_dataset
})

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained("facebook/bart-base")

def tokenize_function(examples):
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )

# Tokenize datasets
tokenized_datasets = datasets.map(tokenize_function, batched=True)

# Save tokenized datasets
tokenized_datasets.save_to_disk("data/tokenized_datasets")