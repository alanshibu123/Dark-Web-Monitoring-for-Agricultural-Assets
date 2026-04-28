#!/usr/bin/env python3
"""Train ML classifiers for keywords with sufficient feedback"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from storage.database import DatabaseManager, DataStorageService
from detector.ml_classifier import KeywordMLClassifier

def main():
    print("="*60)
    print("TRAINING KEYWORD ML CLASSIFIERS")
    print("="*60)
    
    db = DatabaseManager()
    storage = DataStorageService(db)
    
    classifier = KeywordMLClassifier(storage, min_samples=10)
    classifier.initialize()
    
    classifier.train_all_keywords()
    
    print("\n✅ Training complete!")
    print("Models saved to: models/keyword_classifiers/")

if __name__ == "__main__":
    main()