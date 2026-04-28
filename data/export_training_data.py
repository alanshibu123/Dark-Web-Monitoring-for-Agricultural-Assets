#!/usr/bin/env python3
"""Export feedback data for fine-tuning BART"""

import sys
import json
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.database import DatabaseManager

def export_training_data():
    """Export feedback with context as training data"""
    
    db = DatabaseManager()
    training_examples = []
    
    with db.get_session() as session:
        from storage.database import FeedbackModel, KeywordMatchModel
        
        feedbacks = session.query(FeedbackModel).all()
        
        for fb in feedbacks:
            # Get the context (from feedback_comment or match context)
            context = fb.feedback_comment or ''
            
            # Skip if no context
            if not context or len(context) < 20:
                continue
            
            # Map feedback_type to intent
            intent_map = {
                'true_positive': 'credential_dump',
                'false_positive': 'false_positive_sample',
                'false_negative': 'credential_dump'
            }
            
            intent = intent_map.get(fb.feedback_type, 'technical_discussion')
            
            training_examples.append({
                'text': context,
                'intent': intent,
                'source': 'feedback'
            })
        
        # Also add synthetic examples for categories with no feedback
        synthetic_examples = get_synthetic_examples()
        training_examples.extend(synthetic_examples)
    
    # Save to file
    os.makedirs('data', exist_ok=True)
    with open('data/bart_training_data.json', 'w') as f:
        json.dump(training_examples, f, indent=2)
    
    print(f"✅ Exported {len(training_examples)} training examples")
    
    # Show distribution
    intent_counts = {}
    for ex in training_examples:
        intent = ex['intent']
        intent_counts[intent] = intent_counts.get(intent, 0) + 1
    
    print("\n📊 Training Data Distribution:")
    for intent, count in intent_counts.items():
        print(f"  {intent}: {count} examples")

def get_synthetic_examples():
    """Get synthetic examples for categories with no data"""
    return [
        # Credential dump examples
        {"text": "Database dump contains usernames and passwords: admin:admin123, user:pass123", "intent": "credential_dump", "source": "synthetic"},
        {"text": "Leaked credentials: email: admin@agrifarm.com, password: Harvest2024", "intent": "credential_dump", "source": "synthetic"},
        {"text": "API keys exposed: AKIAIOSFODNN7EXAMPLE, secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "intent": "credential_dump", "source": "synthetic"},
        
        # Data breach announcement
        {"text": "We have breached the Ministry of Agriculture servers. Full database exfiltrated.", "intent": "data_breach_announcement", "source": "synthetic"},
        {"text": "BREACH ALERT: AgriFarm Corp has been hacked. Customer data stolen.", "intent": "data_breach_announcement", "source": "synthetic"},
        
        # Marketplace listing
        {"text": "Selling access to compromised CropMonitor database. Price: 2 BTC. DM for sample.", "intent": "marketplace_listing", "source": "synthetic"},
        {"text": "For sale: 500,000 farmer credentials from AgriFarm. $500. Escrow available.", "intent": "marketplace_listing", "source": "synthetic"},
        
        # False positive sample
        {"text": "This is a sample password: example123 for testing purposes only. Not real.", "intent": "false_positive_sample", "source": "synthetic"},
        {"text": "Demo credentials - username: demo, password: demo. For educational use only.", "intent": "false_positive_sample", "source": "synthetic"},
        
        # Technical discussion
        {"text": "How to configure PostgreSQL replication for farm management databases?", "intent": "technical_discussion", "source": "synthetic"},
        {"text": "Anyone using IoT sensors for soil moisture monitoring? Need recommendations.", "intent": "technical_discussion", "source": "synthetic"},
        
        # Agriculture research
        {"text": "Study shows 20% increase in crop yield using optimized NPK ratios", "intent": "agriculture_research", "source": "synthetic"},
        {"text": "Research paper: Impact of irrigation scheduling on water efficiency", "intent": "agriculture_research", "source": "synthetic"},
        
        # Ransomware threat
        {"text": "Your irrigation system is encrypted. Pay 50 BTC within 72 hours or data will be deleted.", "intent": "ransomware_threat", "source": "synthetic"},
        {"text": "We have locked your crop management database. Pay 20 BTC for decryption key.", "intent": "ransomware_threat", "source": "synthetic"},
        
        # Proprietary data sale
        {"text": "Selling YieldPredict v2 algorithm source code. Price: 5 BTC. Includes training data.", "intent": "proprietary_data_sale", "source": "synthetic"},
        {"text": "SoilSense Algorithm parameters for sale. pH calibration and NPK formulas.", "intent": "proprietary_data_sale", "source": "synthetic"},
    ]

if __name__ == "__main__":
    export_training_data()