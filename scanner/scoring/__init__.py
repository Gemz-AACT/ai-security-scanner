"""
Scoring Module
Provides CVSS-style risk scoring for all vulnerability findings
"""

from .scorer import calculate_finding_score, calculate_overall_score, get_risk_rating, generate_score_breakdown