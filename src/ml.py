"""
Machine Learning Analysis Module for Active Directory Security
Contains ML algorithms for anomaly detection, clustering, and pattern analysis
"""

import numpy as np
import pandas as pd
import networkx as nx
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any
from dataclasses import dataclass

# ML and statistical libraries
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scipy import stats


@dataclass
class MLAnalysisResults:
    """Results from ML analysis functions"""
    outliers: List[Dict[str, Any]] = None
    clusters: List[Dict[str, Any]] = None
    anomalies: List[Dict[str, Any]] = None
    patterns: List[Dict[str, Any]] = None
    risk_scores: Dict[str, float] = None
    
    def __post_init__(self):
        if self.outliers is None:
            self.outliers = []
        if self.clusters is None:
            self.clusters = []
        if self.anomalies is None:
            self.anomalies = []
        if self.patterns is None:
            self.patterns = []
        if self.risk_scores is None:
            self.risk_scores = {}


class MLAnalyzer:
    """Machine Learning analysis component for AD security data"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        
    def detect_anomalous_login_patterns(self, auth_data: List[Dict]) -> MLAnalysisResults:
        """Detect anomalous login patterns using ML"""
        try:
            if not auth_data:
                return MLAnalysisResults()
                
            # Convert to DataFrame for easier manipulation
            df = pd.DataFrame(auth_data)
            
            # Feature engineering for login patterns
            features = []
            user_stats = defaultdict(lambda: {
                'total_logins': 0, 'failed_logins': 0, 'unique_computers': set(),
                'login_hours': [], 'login_days': []
            })
            
            # Aggregate user statistics
            for record in auth_data:
                user = record.get('username', 'unknown')
                success = record.get('success_status', True)
                computer = record.get('computer_name', 'unknown')
                timestamp = record.get('timestamp', '')
                
                user_stats[user]['total_logins'] += 1
                if not success:
                    user_stats[user]['failed_logins'] += 1
                user_stats[user]['unique_computers'].add(computer)
                
                # Extract time features if timestamp available
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        user_stats[user]['login_hours'].append(dt.hour)
                        user_stats[user]['login_days'].append(dt.weekday())
                    except:
                        pass
            
            # Create feature vectors
            for user, stats in user_stats.items():
                failure_rate = stats['failed_logins'] / max(stats['total_logins'], 1)
                unique_computers = len(stats['unique_computers'])
                
                hour_entropy = self._calculate_entropy(stats['login_hours']) if stats['login_hours'] else 0
                day_entropy = self._calculate_entropy(stats['login_days']) if stats['login_days'] else 0
                
                features.append({
                    'user': user,
                    'total_logins': stats['total_logins'],
                    'failure_rate': failure_rate,
                    'unique_computers': unique_computers,
                    'hour_entropy': hour_entropy,
                    'day_entropy': day_entropy
                })
            
            if not features:
                return MLAnalysisResults()
            
            # Prepare data for ML
            feature_df = pd.DataFrame(features)
            feature_columns = ['total_logins', 'failure_rate', 'unique_computers', 'hour_entropy', 'day_entropy']
            X = feature_df[feature_columns].fillna(0)
            
            # Anomaly detection
            X_scaled = self.scaler.fit_transform(X)
            anomaly_scores = self.isolation_forest.fit_predict(X_scaled)
            anomaly_scores_prob = self.isolation_forest.score_samples(X_scaled)
            
            # Clustering
            clusters = self.dbscan.fit_predict(X_scaled)
            
            # Identify outliers and clusters
            outliers = []
            for i, (score, prob_score) in enumerate(zip(anomaly_scores, anomaly_scores_prob)):
                if score == -1:  # Anomaly
                    user_data = features[i]
                    user_data['anomaly_score'] = float(prob_score)
                    outliers.append(user_data)
            
            cluster_info = []
            for cluster_id in set(clusters):
                if cluster_id != -1:  # Not noise
                    cluster_users = [features[i]['user'] for i, c in enumerate(clusters) if c == cluster_id]
                    cluster_info.append({
                        'cluster_id': int(cluster_id),
                        'users': cluster_users,
                        'size': len(cluster_users)
                    })
            
            # Calculate risk scores
            risk_scores = {}
            for i, user_data in enumerate(features):
                user = user_data['user']
                risk_score = (
                    user_data['failure_rate'] * 0.4 +
                    min(user_data['unique_computers'] / 10, 1) * 0.3 +
                    (1 - user_data['hour_entropy']) * 0.15 +
                    (1 - user_data['day_entropy']) * 0.15
                )
                risk_scores[user] = float(risk_score)
            
            return MLAnalysisResults(
                outliers=outliers,
                clusters=cluster_info,
                risk_scores=risk_scores
            )
            
        except Exception as e:
            print(f"Error in ML analysis: {str(e)}")
            return MLAnalysisResults()
    
    def analyze_network_topology(self, graph_data: List[Dict]) -> MLAnalysisResults:
        """Analyze network topology for suspicious patterns"""
        try:
            if not graph_data:
                return MLAnalysisResults()
                
            # Build NetworkX graph
            G = nx.Graph()
            for record in graph_data:
                user = record.get('u', {})
                computer = record.get('c', {})
                auth_event = record.get('ae', {})
                
                user_id = user.get('name', f"user_{user.get('id', 'unknown')}")
                computer_id = computer.get('name', f"computer_{computer.get('id', 'unknown')}")
                
                G.add_node(user_id, type='user')
                G.add_node(computer_id, type='computer')
                G.add_edge(user_id, computer_id)
            
            # Calculate network metrics
            patterns = []
            
            # Centrality measures
            degree_centrality = nx.degree_centrality(G)
            betweenness_centrality = nx.betweenness_centrality(G)
            closeness_centrality = nx.closeness_centrality(G)
            
            # Identify high-centrality nodes (potential pivot points)
            high_centrality_threshold = 0.8
            high_centrality_nodes = [
                node for node, centrality in degree_centrality.items() 
                if centrality > high_centrality_threshold
            ]
            
            if high_centrality_nodes:
                patterns.append({
                    'pattern_type': 'high_centrality_nodes',
                    'description': 'Nodes with unusually high network centrality',
                    'nodes': high_centrality_nodes,
                    'risk_level': 'HIGH'
                })
            
            # Community detection
            try:
                communities = list(nx.community.greedy_modularity_communities(G))
                large_communities = [list(community) for community in communities if len(community) > 5]
                
                if large_communities:
                    patterns.append({
                        'pattern_type': 'large_communities',
                        'description': 'Large network communities detected',
                        'communities': large_communities,
                        'risk_level': 'MEDIUM'
                    })
            except:
                pass  # Community detection might fail on some graphs
            
            # Calculate risk scores based on network position
            risk_scores = {}
            for node in G.nodes():
                risk_score = (
                    degree_centrality.get(node, 0) * 0.4 +
                    betweenness_centrality.get(node, 0) * 0.4 +
                    closeness_centrality.get(node, 0) * 0.2
                )
                risk_scores[node] = float(risk_score)
            
            return MLAnalysisResults(
                patterns=patterns,
                risk_scores=risk_scores
            )
            
        except Exception as e:
            print(f"Error in network topology analysis: {str(e)}")
            return MLAnalysisResults()
    
    def detect_time_based_anomalies(self, time_series_data: List[Dict]) -> MLAnalysisResults:
        """Detect time-based anomalies in authentication patterns"""
        try:
            if not time_series_data:
                return MLAnalysisResults()
            
            # Convert to time series
            df = pd.DataFrame(time_series_data)
            if 'timestamp' not in df.columns:
                return MLAnalysisResults()
            
            # Extract time features
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6])
            df['is_off_hours'] = (df['hour'] < 6) | (df['hour'] > 20)
            
            # Detect anomalies
            anomalies = []
            
            # Off-hours activity anomalies
            off_hours_count = df[df['is_off_hours']].shape[0]
            if off_hours_count > len(df) * 0.3:  # More than 30% off-hours activity
                anomalies.append({
                    'anomaly_type': 'excessive_off_hours_activity',
                    'description': f'High off-hours activity: {off_hours_count} events',
                    'severity': 'MEDIUM'
                })
            
            # Weekend activity anomalies
            weekend_count = df[df['is_weekend']].shape[0]
            if weekend_count > len(df) * 0.4:  # More than 40% weekend activity
                anomalies.append({
                    'anomaly_type': 'excessive_weekend_activity',
                    'description': f'High weekend activity: {weekend_count} events',
                    'severity': 'LOW'
                })
            
            return MLAnalysisResults(anomalies=anomalies)
            
        except Exception as e:
            print(f"Error in time-based anomaly detection: {str(e)}")
            return MLAnalysisResults()
    
    def _calculate_entropy(self, data: List) -> float:
        """Calculate entropy of a data series"""
        if not data:
            return 0
        
        value_counts = Counter(data)
        probabilities = [count / len(data) for count in value_counts.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        
        # Normalize by maximum possible entropy
        max_entropy = np.log2(len(value_counts)) if len(value_counts) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0


def analyze_comprehensive_ml(auth_data: List[Dict], graph_data: List[Dict]) -> MLAnalysisResults:
    """Run comprehensive ML analysis on all available data"""
    analyzer = MLAnalyzer()
    
    # Run all ML analyses
    login_results = analyzer.detect_anomalous_login_patterns(auth_data)
    network_results = analyzer.analyze_network_topology(graph_data)
    time_results = analyzer.detect_time_based_anomalies(auth_data)
    
    # Combine results
    combined_results = MLAnalysisResults(
        outliers=login_results.outliers + network_results.outliers,
        clusters=login_results.clusters + network_results.clusters,
        anomalies=time_results.anomalies,
        patterns=network_results.patterns,
        risk_scores={**login_results.risk_scores, **network_results.risk_scores}
    )
    
    return combined_results