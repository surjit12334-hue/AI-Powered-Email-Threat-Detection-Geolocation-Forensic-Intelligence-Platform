import os
import json
import numpy as np
from datetime import datetime


# Sample training dataset for phishing detection
TRAINING_DATA = [
    # Phishing examples
    {"subject": "URGENT: Your account has been suspended", "body": "Click here to verify your account immediately or it will be permanently deleted. Verify now: http://secure-login-verify.xyz/account", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 1, "dmarc_fail": 1, "reply_mismatch": 1, "urgency": 3, "phishing_keywords": 4, "caps_ratio": 0.15, "label": 1},
    {"subject": "PayPal Security Alert - Unauthorized Access Detected", "body": "We detected unauthorized access to your PayPal account. Please verify your identity within 24 hours or your account will be limited. Login here: http://paypal-secure123.top/verify", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 0, "dmarc_fail": 1, "reply_mismatch": 1, "urgency": 2, "phishing_keywords": 5, "caps_ratio": 0.08, "label": 1},
    {"subject": "CONGRATULATIONS! You've Won $1,000,000", "body": "You have been selected as the winner of our international lottery. Claim your prize of $1,000,000 immediately. Send your bank details to claim@lottery-winner.ml", "urls": 0, "suspicious_urls": 0, "spf_fail": 1, "dkim_fail": 1, "dmarc_fail": 1, "reply_mismatch": 1, "urgency": 2, "phishing_keywords": 3, "caps_ratio": 0.22, "label": 1},
    {"subject": "Microsoft Account Security Warning", "body": "Unusual sign-in activity detected on your Microsoft account. Someone tried to sign in from Russia. Verify your account now or it will be locked. http://microsoft-security-verify.tk/account", "urls": 1, "suspicious_urls": 1, "spf_fail": 0, "dkim_fail": 1, "dmarc_fail": 1, "reply_mismatch": 0, "urgency": 3, "phishing_keywords": 4, "caps_ratio": 0.05, "label": 1},
    {"subject": "Amazon Order Confirmation #892-4712398-1234", "body": "Your recent order of iPhone 15 Pro Max for $1,299.99 has been confirmed. If you did not make this order, click here to cancel: http://amazon-orders-verify.club/cancel", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 1, "dmarc_fail": 0, "reply_mismatch": 1, "urgency": 2, "phishing_keywords": 3, "caps_ratio": 0.03, "label": 1},
    {"subject": "Your Netflix subscription needs updating", "body": "Your payment method on file has expired. Update your billing information within 48 hours to avoid service interruption. Update now: http://netflix-billing-update.gq/update", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 1, "dmarc_fail": 1, "reply_mismatch": 0, "urgency": 2, "phishing_keywords": 2, "caps_ratio": 0.02, "label": 1},
    {"subject": "Action Required: Password Expiration Notice", "body": "Your corporate email password will expire in 24 hours. Click the link below to reset your password immediately: http://corporate-reset.ml/password", "urls": 1, "suspicious_urls": 1, "spf_fail": 0, "dkim_fail": 1, "dmarc_fail": 0, "reply_mismatch": 1, "urgency": 3, "phishing_keywords": 3, "caps_ratio": 0.04, "label": 1},
    {"subject": "DHL Express: Your package is on hold", "body": "Your shipment cannot be delivered due to incomplete address. Please confirm your delivery details and pay the shipping fee of $3.99. Track here: http://dhl-delivery-confirm.pw/track", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 0, "dmarc_fail": 1, "reply_mismatch": 0, "urgency": 2, "phishing_keywords": 2, "caps_ratio": 0.06, "label": 1},
    {"subject": "IRS Tax Refund Notification", "body": "You are eligible for a tax refund of $4,231.00. Submit your claim form within 72 hours to receive your refund. Claim now: http://irs-refund-2024.xyz/claim", "urls": 1, "suspicious_urls": 1, "spf_fail": 1, "dkim_fail": 1, "dmarc_fail": 1, "reply_mismatch": 1, "urgency": 3, "phishing_keywords": 4, "caps_ratio": 0.09, "label": 1},
    {"subject": "Google Security Alert", "body": "New sign-in from Chrome on Windows. If this wasn't you, secure your account immediately. Review activity: http://google-security-review.tk/activity", "urls": 1, "suspicious_urls": 1, "spf_fail": 0, "dkim_fail": 1, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 2, "phishing_keywords": 3, "caps_ratio": 0.03, "label": 1},

    # Legitimate examples
    {"subject": "Weekly Team Meeting Notes", "body": "Hi team, here are the notes from today's meeting. Please review the action items before our next sync. Best regards, Sarah", "urls": 0, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.02, "label": 0},
    {"subject": "Re: Project Update Q4", "body": "Thanks for the update. I've reviewed the document and have a few comments. Let's schedule a call to discuss the timeline.", "urls": 0, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.01, "label": 0},
    {"subject": "Invoice #INV-2024-001", "body": "Please find attached the invoice for services rendered in November 2024. Payment is due within 30 days. Let me know if you have any questions.", "urls": 0, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.03, "label": 0},
    {"subject": "Welcome to GitHub", "body": "Thanks for signing up for GitHub! You can now create repositories, collaborate with others, and start building amazing projects.", "urls": 1, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.04, "label": 0},
    {"subject": "Your Amazon order has shipped", "body": "Good news! Your order #114-3847562-1234567 has shipped. You can track your package using the link in your account.", "urls": 1, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.02, "label": 0},
    {"subject": "Meeting Tomorrow at 3 PM", "body": "Just a reminder that we have a meeting scheduled for tomorrow at 3 PM in Conference Room B. Please bring your quarterly reports.", "urls": 0, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.01, "label": 0},
    {"subject": "Password Reset Request", "body": "You requested a password reset for your account. Click the link below to set a new password. This link expires in 1 hour.", "urls": 1, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 1, "phishing_keywords": 1, "caps_ratio": 0.02, "label": 0},
    {"subject": "Monthly Newsletter - December 2024", "body": "Here's your monthly roundup of news and updates. Check out our latest blog posts and upcoming events.", "urls": 3, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.05, "label": 0},
    {"subject": "Re: Lunch Plans", "body": "How about that new Italian place on Main Street? I heard they have great pasta. Let me know if you're interested!", "urls": 0, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.01, "label": 0},
    {"subject": "Job Application Received", "body": "Thank you for applying to the Software Engineer position at TechCorp. We have received your application and will review it shortly.", "urls": 1, "suspicious_urls": 0, "spf_fail": 0, "dkim_fail": 0, "dmarc_fail": 0, "reply_mismatch": 0, "urgency": 0, "phishing_keywords": 0, "caps_ratio": 0.03, "label": 0},
]


def extract_training_features(data):
    """Extract feature vectors from training data."""
    feature_names = [
        'urls', 'suspicious_urls', 'spf_fail', 'dkim_fail', 'dmarc_fail',
        'reply_mismatch', 'urgency', 'phishing_keywords', 'caps_ratio'
    ]

    X = []
    y = []
    for sample in data:
        features = [sample.get(f, 0) for f in feature_names]
        X.append(features)
        y.append(sample['label'])

    return np.array(X), np.array(y), feature_names


def train_model():
    """Train a simple phishing detection model using scikit-learn."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    import joblib

    X, y, feature_names = extract_training_features(TRAINING_DATA)

    # Train Random Forest
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    rf_model.fit(X, y)

    # Train Logistic Regression
    lr_model = LogisticRegression(random_state=42, max_iter=1000)
    lr_model.fit(X, y)

    # Cross-validation scores
    rf_scores = cross_val_score(rf_model, X, y, cv=3)
    lr_scores = cross_val_score(lr_model, X, y, cv=3)

    # Save models
    model_dir = os.path.join(os.path.dirname(__file__), 'model')
    os.makedirs(model_dir, exist_ok=True)

    joblib.dump(rf_model, os.path.join(model_dir, 'random_forest.joblib'))
    joblib.dump(lr_model, os.path.join(model_dir, 'logistic_regression.joblib'))
    joblib.dump(feature_names, os.path.join(model_dir, 'feature_names.joblib'))

    # Save training metadata
    metadata = {
        'trained_at': datetime.utcnow().isoformat(),
        'training_samples': len(TRAINING_DATA),
        'feature_names': feature_names,
        'rf_cv_score': float(np.mean(rf_scores)),
        'lr_cv_score': float(np.mean(lr_scores)),
        'model_version': '1.0',
    }
    with open(os.path.join(model_dir, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2)

    return {
        'rf_accuracy': float(np.mean(rf_scores)),
        'lr_accuracy': float(np.mean(lr_scores)),
        'features': feature_names,
        'samples': len(TRAINING_DATA),
    }


if __name__ == '__main__':
    result = train_model()
    print(f"Training complete!")
    print(f"Random Forest CV Accuracy: {result['rf_accuracy']:.2%}")
    print(f"Logistic Regression CV Accuracy: {result['lr_accuracy']:.2%}")
