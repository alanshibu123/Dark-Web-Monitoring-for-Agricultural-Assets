"""
ML Classifier for keyword context
Trains a separate model for each keyword with enough feedback
"""

import os
import pickle
import logging
import numpy as np
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from datetime import datetime
from typing import List, Dict, Any

class KeywordMLClassifier:
    """
    Train a separate ML model for each keyword that has enough feedback
    """
    
    def __init__(self, storage_service, min_samples: int = 10):
        """
        Args:
            storage_service: Database service to fetch feedback
            min_samples: Minimum feedback samples needed to train a model
        """
        self.storage = storage_service
        self.min_samples = min_samples
        self.logger = logging.getLogger(__name__)
        self.models = {}  # keyword -> trained model
        self.feature_extractor = None
        self.last_trained = {}
        
    def initialize(self):
        """Initialize feature extractor and load existing models"""
        from detector.feature_extractor import FeatureExtractor
        self.feature_extractor = FeatureExtractor()
        self._load_models()
        
    def _load_models(self):
        """Load previously saved models from disk"""
        model_dir = "models/keyword_classifiers"
        os.makedirs(model_dir, exist_ok=True)
        
        for filename in os.listdir(model_dir):
            if filename.endswith('.pkl'):
                keyword = filename.replace('.pkl', '')
                with open(os.path.join(model_dir, filename), 'rb') as f:
                    self.models[keyword] = pickle.load(f)
                self.logger.info(f"Loaded model for keyword: {keyword}")
    
    def _save_model(self, keyword: str, model):
        """Save model to disk"""
        model_dir = "models/keyword_classifiers"
        os.makedirs(model_dir, exist_ok=True)
        
        with open(os.path.join(model_dir, f"{keyword}.pkl"), 'wb') as f:
            pickle.dump(model, f)
        self.logger.info(f"Saved model for keyword: {keyword}")
    
    def train_for_keyword(self, keyword: str):
        """
        Train a classifier for a specific keyword using feedback data
        """
        # Get all feedback for this keyword
        feedbacks = self._get_feedback_for_keyword(keyword)
        
        if len(feedbacks) < self.min_samples:
            self.logger.info(f"Not enough samples for '{keyword}': {len(feedbacks)}/{self.min_samples}")
            return False
        
        # Prepare training data
        X = []
        y = []
        
        for feedback in feedbacks:
            # Extract features from the context
            context = feedback.get('context', '')
            match_text = feedback.get('matched_text', keyword)
            
            features = self.feature_extractor.extract_features(
                match_text=match_text,
                context=context
            )
            
            X.append(features)
            # 1 = true_positive, 0 = false_positive
            label = 1 if feedback['feedback_type'] == 'true_positive' else 0
            y.append(label)
        
        if len(X) < self.min_samples:
            return False
        
        # Train Random Forest classifier
        base_model = RandomForestClassifier(
            n_estimators=50,
            max_depth=5,
            random_state=42
        )
        
        # Calibrate for probability output
        model = CalibratedClassifierCV(base_model, cv=3)
        model.fit(X, y)
        
        # Store and save model
        self.models[keyword] = model
        self._save_model(keyword, model)
        self.last_trained[keyword] = datetime.now()
        
        # Calculate accuracy on training data
        predictions = model.predict(X)
        accuracy = sum(predictions == y) / len(y)
        
        self.logger.info(f"Trained model for '{keyword}' with {len(X)} samples, accuracy: {accuracy:.2f}")
        return True
    
    def predict_confidence(self, keyword: str, match_text: str, context: str) -> float:
        """
        Predict confidence using keyword-specific model if available
        
        Returns:
            Confidence score (0-1)
        """
        # If no model for this keyword, return None (use fallback)
        if keyword not in self.models:
            return None
        
        # Extract features
        features = self.feature_extractor.extract_features(
            match_text=match_text,
            context=context
        )
        
        # Get probability of being true positive
        proba = self.models[keyword].predict_proba([features])[0]
        confidence = proba[1]  # Index 1 = true_positive probability
        
        # Apply confidence boost/shrink based on model certainty
        # More certain models get more extreme scores
        if len(self.models[keyword].classes_) > 1:
            # Adjust confidence based on prediction margin
            margin = abs(proba[1] - 0.5) * 2  # 0 to 1 range
            if proba[1] > 0.5:
                confidence = 0.5 + (proba[1] - 0.5) * (1 + margin * 0.3)
            else:
                confidence = proba[1] * (1 - margin * 0.3)
        
        return max(0.05, min(0.95, confidence))
    
    def _get_feedback_for_keyword(self, keyword: str) -> List[Dict]:
        """Retrieve feedback data for a keyword from database"""
        with self.storage.db.get_session() as session:
            from storage.database import FeedbackModel, KeywordMatchModel
            
            feedbacks = session.query(FeedbackModel).filter(
                FeedbackModel.keyword == keyword
            ).all()
            
            result = []
            for fb in feedbacks:
                # Get the original match context
                match_context = ''
                if fb.match_id:
                    match = session.query(KeywordMatchModel).filter(
                        KeywordMatchModel.id == fb.match_id
                    ).first()
                    if match:
                        match_context = match.context
                
                result.append({
                    'feedback_type': fb.feedback_type,
                    'context': match_context or fb.feedback_comment or '',
                    'matched_text': fb.keyword
                })
            
            return result
    
    def train_all_keywords(self):
        """Train models for all keywords with sufficient feedback"""
        with self.storage.db.get_session() as session:
            from storage.database import FeedbackModel
            from sqlalchemy import func
            
            # Get keywords with enough feedback
            keyword_counts = session.query(
                FeedbackModel.keyword,
                func.count(FeedbackModel.id).label('count')
            ).group_by(FeedbackModel.keyword).having(
                func.count(FeedbackModel.id) >= self.min_samples
            ).all()
            
            for keyword, count in keyword_counts:
                self.logger.info(f"Training model for '{keyword}' ({count} samples)")
                self.train_for_keyword(keyword)