"""
AI/ML models for anomaly detection in the IoT Risk Detection System.
Includes Isolation Forest, DBSCAN, and LSTM models.
"""
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import pickle
import os

from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping

from ..utils.config import config
from ..database.models import TrafficRecord, AnomalyModel
from ..database.database import get_db_session

logger = logging.getLogger(__name__)

class AnomalyDetectionModel:
    """Base class for anomaly detection models."""
    
    def __init__(self, model_type: str, model_name: str):
        self.model_type = model_type
        self.model_name = model_name
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = os.path.join(config.MODELS_DIR, f"{model_name}.pkl")
        self.scaler_path = os.path.join(config.MODELS_DIR, f"{model_name}_scaler.pkl")
    
    def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> Dict:
        """Train the model with given data."""
        raise NotImplementedError
    
    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict anomalies in the data."""
        raise NotImplementedError
    
    def predict_proba(self, data: np.ndarray) -> np.ndarray:
        """Predict anomaly probabilities."""
        raise NotImplementedError
    
    def save_model(self) -> bool:
        """Save the trained model to disk."""
        try:
            os.makedirs(config.MODELS_DIR, exist_ok=True)
            
            # Save model
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            # Save scaler
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            logger.info(f"Model {self.model_name} saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model {self.model_name}: {e}")
            return False
    
    def load_model(self) -> bool:
        """Load the trained model from disk."""
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"Model file {self.model_path} not found")
                return False
            
            # Load model
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Load scaler
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            self.is_trained = True
            logger.info(f"Model {self.model_name} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model {self.model_name}: {e}")
            return False
    
    def get_model_info(self) -> Dict:
        """Get information about the model."""
        return {
            'model_type': self.model_type,
            'model_name': self.model_name,
            'is_trained': self.is_trained,
            'model_path': self.model_path,
            'scaler_path': self.scaler_path
        }

class IsolationForestModel(AnomalyDetectionModel):
    """Isolation Forest model for anomaly detection."""
    
    def __init__(self, model_name: str = "isolation_forest"):
        super().__init__("isolation_forest", model_name)
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
    
    def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> Dict:
        """Train the Isolation Forest model."""
        try:
            logger.info(f"Training Isolation Forest model with {len(data)} samples")
            
            # Scale the data
            data_scaled = self.scaler.fit_transform(data)
            
            # Train the model
            start_time = datetime.utcnow()
            self.model.fit(data_scaled)
            training_time = (datetime.utcnow() - start_time).total_seconds()
            
            self.is_trained = True
            
            # Calculate training metrics
            predictions = self.model.predict(data_scaled)
            anomaly_score = self.model.score_samples(data_scaled)
            
            metrics = {
                'training_samples': len(data),
                'training_time': training_time,
                'anomaly_ratio': np.mean(predictions == -1),
                'mean_anomaly_score': np.mean(anomaly_score),
                'std_anomaly_score': np.std(anomaly_score)
            }
            
            logger.info(f"Isolation Forest training completed. Metrics: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training Isolation Forest model: {e}")
            raise
    
    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict anomalies (1 for normal, -1 for anomaly)."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data)
        return self.model.predict(data_scaled)
    
    def predict_proba(self, data: np.ndarray) -> np.ndarray:
        """Predict anomaly scores (lower values indicate anomalies)."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data)
        return self.model.score_samples(data_scaled)

class DBSCANModel(AnomalyDetectionModel):
    """DBSCAN model for anomaly detection."""
    
    def __init__(self, model_name: str = "dbscan"):
        super().__init__("dbscan", model_name)
        self.model = DBSCAN(
            eps=0.5,
            min_samples=5,
            metric='euclidean'
        )
    
    def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> Dict:
        """Train the DBSCAN model."""
        try:
            logger.info(f"Training DBSCAN model with {len(data)} samples")
            
            # Scale the data
            data_scaled = self.scaler.fit_transform(data)
            
            # Train the model
            start_time = datetime.utcnow()
            cluster_labels = self.model.fit_predict(data_scaled)
            training_time = (datetime.utcnow() - start_time).total_seconds()
            
            self.is_trained = True
            
            # Calculate training metrics
            n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
            n_noise = list(cluster_labels).count(-1)
            
            metrics = {
                'training_samples': len(data),
                'training_time': training_time,
                'n_clusters': n_clusters,
                'n_noise_points': n_noise,
                'noise_ratio': n_noise / len(data)
            }
            
            logger.info(f"DBSCAN training completed. Metrics: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training DBSCAN model: {e}")
            raise
    
    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict anomalies (cluster labels, -1 for noise/anomalies)."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data)
        return self.model.fit_predict(data_scaled)
    
    def predict_proba(self, data: np.ndarray) -> np.ndarray:
        """Calculate distance to nearest cluster center as anomaly score."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data)
        
        # Calculate distances to cluster centers
        if hasattr(self.model, 'cluster_centers_'):
            distances = []
            for point in data_scaled:
                min_distance = np.inf
                for center in self.model.cluster_centers_:
                    distance = np.linalg.norm(point - center)
                    min_distance = min(min_distance, distance)
                distances.append(min_distance)
            return np.array(distances)
        else:
            # Fallback: use distance to nearest neighbor
            from sklearn.neighbors import NearestNeighbors
            nbrs = NearestNeighbors(n_neighbors=1).fit(data_scaled)
            distances, _ = nbrs.kneighbors(data_scaled)
            return distances.flatten()

class LSTMModel(AnomalyDetectionModel):
    """LSTM model for time-series anomaly detection."""
    
    def __init__(self, model_name: str = "lstm", sequence_length: int = 10):
        super().__init__("lstm", model_name)
        self.sequence_length = sequence_length
        self.scaler = MinMaxScaler()  # Use MinMaxScaler for LSTM
        self.model = self._build_model()
    
    def _build_model(self) -> Sequential:
        """Build the LSTM model architecture."""
        model = Sequential([
            LSTM(64, return_sequences=True, input_shape=(self.sequence_length, 1)),
            Dropout(0.2),
            LSTM(32, return_sequences=False),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def _prepare_sequences(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequences for LSTM training."""
        sequences = []
        targets = []
        
        for i in range(len(data) - self.sequence_length):
            sequence = data[i:i + self.sequence_length]
            target = data[i + self.sequence_length]
            sequences.append(sequence)
            targets.append(target)
        
        return np.array(sequences), np.array(targets)
    
    def train(self, data: np.ndarray, labels: Optional[np.ndarray] = None) -> Dict:
        """Train the LSTM model."""
        try:
            logger.info(f"Training LSTM model with {len(data)} samples")
            
            # Scale the data
            data_scaled = self.scaler.fit_transform(data.reshape(-1, 1))
            
            # Prepare sequences
            X, y = self._prepare_sequences(data_scaled)
            
            # Early stopping callback
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            # Train the model
            start_time = datetime.utcnow()
            history = self.model.fit(
                X, y,
                epochs=100,
                batch_size=32,
                validation_split=0.2,
                callbacks=[early_stopping],
                verbose=0
            )
            training_time = (datetime.utcnow() - start_time).total_seconds()
            
            self.is_trained = True
            
            # Calculate training metrics
            y_pred = self.model.predict(X)
            y_pred_binary = (y_pred > 0.5).astype(int)
            
            metrics = {
                'training_samples': len(data),
                'training_time': training_time,
                'epochs_trained': len(history.history['loss']),
                'final_loss': history.history['loss'][-1],
                'final_accuracy': history.history['accuracy'][-1],
                'sequence_length': self.sequence_length
            }
            
            logger.info(f"LSTM training completed. Metrics: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training LSTM model: {e}")
            raise
    
    def predict(self, data: np.ndarray) -> np.ndarray:
        """Predict anomalies (1 for normal, 0 for anomaly)."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data.reshape(-1, 1))
        X, _ = self._prepare_sequences(data_scaled)
        
        predictions = self.model.predict(X)
        return (predictions > 0.5).astype(int)
    
    def predict_proba(self, data: np.ndarray) -> np.ndarray:
        """Predict anomaly probabilities."""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        data_scaled = self.scaler.transform(data.reshape(-1, 1))
        X, _ = self._prepare_sequences(data_scaled)
        
        return self.model.predict(X).flatten()
    
    def save_model(self) -> bool:
        """Save the trained LSTM model to disk."""
        try:
            os.makedirs(config.MODELS_DIR, exist_ok=True)
            
            # Save Keras model
            model_path = os.path.join(config.MODELS_DIR, f"{self.model_name}.h5")
            self.model.save(model_path)
            
            # Save scaler
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            # Save sequence length
            seq_path = os.path.join(config.MODELS_DIR, f"{self.model_name}_seq.pkl")
            with open(seq_path, 'wb') as f:
                pickle.dump(self.sequence_length, f)
            
            logger.info(f"LSTM model {self.model_name} saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving LSTM model {self.model_name}: {e}")
            return False
    
    def load_model(self) -> bool:
        """Load the trained LSTM model from disk."""
        try:
            model_path = os.path.join(config.MODELS_DIR, f"{self.model_name}.h5")
            if not os.path.exists(model_path):
                logger.warning(f"LSTM model file {model_path} not found")
                return False
            
            # Load Keras model
            self.model = load_model(model_path)
            
            # Load scaler
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            # Load sequence length
            seq_path = os.path.join(config.MODELS_DIR, f"{self.model_name}_seq.pkl")
            if os.path.exists(seq_path):
                with open(seq_path, 'rb') as f:
                    self.sequence_length = pickle.load(f)
            
            self.is_trained = True
            logger.info(f"LSTM model {self.model_name} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading LSTM model {self.model_name}: {e}")
            return False

class AnomalyDetectionManager:
    """Manages multiple anomaly detection models."""
    
    def __init__(self):
        self.models = {}
        self.active_model = None
    
    def create_model(self, model_type: str, model_name: str, **kwargs) -> AnomalyDetectionModel:
        """Create a new anomaly detection model."""
        if model_type == "isolation_forest":
            model = IsolationForestModel(model_name)
        elif model_type == "dbscan":
            model = DBSCANModel(model_name)
        elif model_type == "lstm":
            sequence_length = kwargs.get('sequence_length', 10)
            model = LSTMModel(model_name, sequence_length)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        self.models[model_name] = model
        return model
    
    def get_model(self, model_name: str) -> Optional[AnomalyDetectionModel]:
        """Get a model by name."""
        return self.models.get(model_name)
    
    def train_model(self, model_name: str, data: np.ndarray, 
                   labels: Optional[np.ndarray] = None) -> Dict:
        """Train a specific model."""
        model = self.get_model(model_name)
        if not model:
            raise ValueError(f"Model {model_name} not found")
        
        return model.train(data, labels)
    
    def predict_anomalies(self, data: np.ndarray, model_name: Optional[str] = None) -> Dict:
        """Predict anomalies using the specified model or ensemble."""
        if model_name:
            model = self.get_model(model_name)
            if not model:
                raise ValueError(f"Model {model_name} not found")
            
            predictions = model.predict(data)
            probabilities = model.predict_proba(data)
            
            return {
                'model_name': model_name,
                'predictions': predictions,
                'probabilities': probabilities
            }
        else:
            # Ensemble prediction
            return self._ensemble_predict(data)
    
    def _ensemble_predict(self, data: np.ndarray) -> Dict:
        """Perform ensemble prediction using all trained models."""
        predictions = {}
        probabilities = {}
        
        for name, model in self.models.items():
            if model.is_trained:
                try:
                    pred = model.predict(data)
                    prob = model.predict_proba(data)
                    predictions[name] = pred
                    probabilities[name] = prob
                except Exception as e:
                    logger.error(f"Error predicting with model {name}: {e}")
        
        # Combine predictions (simple voting)
        if predictions:
            # Convert to numpy arrays for easier manipulation
            pred_arrays = [np.array(pred) for pred in predictions.values()]
            
            # For isolation forest and DBSCAN, -1 means anomaly
            # For LSTM, 0 means anomaly
            # Normalize to 0 (normal) and 1 (anomaly)
            normalized_preds = []
            for i, (name, pred) in enumerate(predictions.items()):
                if name == "lstm":
                    # LSTM: 0=anomaly, 1=normal -> 0=normal, 1=anomaly
                    normalized_preds.append(1 - pred)
                else:
                    # Isolation Forest/DBSCAN: -1=anomaly, 1=normal -> 0=normal, 1=anomaly
                    normalized_preds.append((pred == -1).astype(int))
            
            # Ensemble prediction (majority vote)
            ensemble_pred = np.mean(normalized_preds, axis=0)
            final_pred = (ensemble_pred > 0.5).astype(int)
            
            return {
                'ensemble': True,
                'model_predictions': predictions,
                'model_probabilities': probabilities,
                'ensemble_prediction': final_pred,
                'ensemble_confidence': ensemble_pred
            }
        
        return {'ensemble': False, 'error': 'No trained models available'}
    
    def save_all_models(self) -> Dict:
        """Save all trained models."""
        results = {}
        for name, model in self.models.items():
            if model.is_trained:
                results[name] = model.save_model()
        return results
    
    def load_all_models(self) -> Dict:
        """Load all available models."""
        results = {}
        for name, model in self.models.items():
            results[name] = model.load_model()
        return results
    
    def get_model_status(self) -> Dict:
        """Get status of all models."""
        status = {}
        for name, model in self.models.items():
            status[name] = {
                'type': model.model_type,
                'is_trained': model.is_trained,
                'model_path': model.model_path
            }
        return status

# Global anomaly detection manager
anomaly_manager = AnomalyDetectionManager() 