#!/usr/bin/env python3
from typing import Any, Dict
import time
import numpy as np

import orjson

import ipal_iids.settings as settings
from ids.ids import MetaIDS
from ids.kitsune.feature_extractor import FeatureExtractor
from ids.kitsune.KitNET.KitNET import KitNET


class Kitsune(MetaIDS):
    _name = "Kitsune"
    _description = "Kitsune 🦊"
    _requires = ["train.ipal", "live.ipal"]
    _kitsune_default_settings = {
        "offset_live_timestamps": True,
        "max_host": 10000000000,
        "max_sess": 10000000000,
        "threshold": 10,
        "max_autoencoder_size": 10,
        "fm_grace_period": 10000,
        "learning_rate": 0.1,
        "hidden_ratio": 0.75,
        "lambdas": [5, 3, 1, 0.1, 0.01],
        "enable_timing": False,
        "timing_log_interval": 100,
        "timing_detailed_interval": 1000,
        "performance_report_on_exit": True,
        "features_regexp": {
            "srcMAC": [
                "src",
                r"([abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d])",
            ],
            "dstMAC": [
                "dest",
                r"([abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d]\.[abcdef\d][abcdef\d])",
            ],
            "srcIP": ["src", r"(\d+\.\d+\.\d+\.\d+)"],
            "dstIP": ["dest", r"(\d+\.\d+\.\d+\.\d+)"],
            "srcPort": ["src", r"\d+\.\d+\.\d+\.\d+:(\d+)"],
            "dstPort": ["src", r"\d+\.\d+\.\d+\.\d+:(\d+)"],
            "datagramSize": ["length", r"(.*)"],
            "timestamp": ["timestamp", r"(.*)"],
        },
        "stats": [
            # MAC.IP: Stats on src MAC-IP relationships
            {
                "name": "MIstat",
                "type": "1D",
                "features": {
                    "ID1": ["srcMAC", "srcIP"],
                    "t1": "timestamp",
                    "v1": "datagramSize",
                },
                "typediff": False,
                "limit": "mac_hostlimit",
            },
            # Host-Host BW: Stats on the dual traffic behavior between srcIP and dstIP
            {
                "name": "HHstat",
                "type": "1D2D",
                "features": {
                    "ID1": ["srcIP"],
                    "ID2": ["dstIP"],
                    "t1": "timestamp",
                    "v1": "datagramSize",
                },
                "typediff": False,
                "limit": "hostlimit",
            },
            # Host-Host jitter: Stats on the dual traffic behavior between srcIP and dstIP
            {
                "name": "HHstat_ji",
                "type": "1D",
                "features": {
                    "ID1": ["srcIP", "dstIP"],
                    "t1": "timestamp",
                    "v1": "_zero",
                },
                "typediff": True,
                "limit": "hostlimit",
            },
            # Hostport-Hostport BW: Stats on the dual traffic behavior between srcIP:srcPort and dstIP:dstPort
            {
                "name": "HpHpstat",
                "type": "1D2D",
                "features": {
                    "ID1": ["srcIP", "srcPort"],
                    "ID2": ["dstIP", "dstPort"],
                    "t1": "timestamp",
                    "v1": "datagramSize",
                },
                "typediff": False,
                "limit": "sessionlimit",
            },
        ],
    }
    _supports_preprocessor = False
    _fe: FeatureExtractor
    _detector: KitNET

    def __init__(self, name=None):
        super().__init__(name=name)
        self._add_default_settings(self._kitsune_default_settings)
        self._last_training_ts = 0.0
        self._last_training_ts_delta = 0.0
        self._ts_offset = 0.0
        self._first_alert_logged = False

        self.inference_times = []
        self.inference_count = 0

    def _log_first_alert(self, msg: Dict[str, Any], score: float):
        if self._first_alert_logged:
            return

        if hasattr(settings, 'logger'):
            settings.logger.info(
                "Kitsune first alert: "
                f"timestamp={msg.get('timestamp')} "
                f"src={msg.get('src')} dest={msg.get('dest')} "
                f"activity={msg.get('activity')} type={msg.get('type')} data={msg.get('data')} "
                f"score={score:.6f} threshold={self.settings['threshold']}"
                f"maclicisou={msg.get('malicious', False)}"
            )

        # self._first_alert_logged = True

    def train(self, ipal=None, state=None):
        self._fe = FeatureExtractor(
            self.settings["features_regexp"],
            self.settings["lambdas"],
            self.settings["max_host"],
            self.settings["max_sess"],
            self.settings["stats"],
        )

        self._detector = KitNET(
            n=self._fe.get_num_features(),
            max_autoencoder_size=self.settings["max_autoencoder_size"],
            FM_grace_period=self.settings["fm_grace_period"],
            learning_rate=self.settings["learning_rate"],
            hidden_ratio=self.settings["hidden_ratio"],
        )

        with self._open_file(ipal) as f:
            for line in f:
                ipal_msg = orjson.loads(line)

                ts = ipal_msg["timestamp"]
                self._last_training_ts_delta = ts - self._last_training_ts
                self._last_training_ts = ts

                features = self._fe.extract_features(ipal_msg)
                self._detector.train(features)
        
        # Reset timing stats after training
        self.reset_timing_stats()
        if hasattr(settings, 'logger'):
            settings.logger.info("Kitsune training completed. Timing statistics reset for live inference.")

    def new_ipal_msg(self, msg: Dict[str, Any]):
        # Start timing
        if self.settings.get("enable_timing", True):
            start_time = time.perf_counter()
        
        if self.settings["offset_live_timestamps"] and self._ts_offset == 0.0:
            self._ts_offset = (
                self._last_training_ts + self._last_training_ts_delta - msg["timestamp"]
            )

        features = self._fe.extract_features(msg, timestamp_offset=self._ts_offset)
        score = self._detector.execute(features)

        result = bool(score > self.settings["threshold"]), float(score)

        if result[0]:
            self._log_first_alert(msg, float(score))

        # End timing and comprehensive logging
        if self.settings.get("enable_timing", True):
            end_time = time.perf_counter()
            inference_time = (end_time - start_time) * 1000
            
            self.inference_times.append(inference_time)
            self.inference_count += 1
            
            # Basic periodic logging
            log_interval = self.settings.get("timing_log_interval", 100)
            if self.inference_count % log_interval == 0:
                recent_times = self.inference_times[-log_interval:]
                avg_time = sum(recent_times) / len(recent_times)
                min_time = min(recent_times)
                max_time = max(recent_times)
                
                if hasattr(settings, 'logger'):
                    settings.logger.info(
                        f"Kitsune Timing (last {log_interval}): "
                        f"Avg={avg_time:.3f}ms, Min={min_time:.3f}ms, Max={max_time:.3f}ms"
                    )
            
            # Detailed statistics logging
            detailed_interval = self.settings.get("timing_detailed_interval", 1000)
            if self.inference_count % detailed_interval == 0:
                stats = self.get_timing_stats()
                if stats and hasattr(settings, 'logger'):
                    settings.logger.info(
                        f"Kitsune Detailed Performance (n={stats['total_inferences']}): "
                        f"Median={stats['median_time_ms']:.3f}ms, "
                        f"P95={stats['p95_time_ms']:.3f}ms, "
                        f"P99={stats['p99_time_ms']:.3f}ms, "
                        f"Std={stats['std_time_ms']:.3f}ms"
                    )

        return result

    def get_timing_stats(self):
        if not self.inference_times:
            return None
        
        times = np.array(self.inference_times)
        
        return {
            "total_inferences": len(self.inference_times),
            "avg_time_ms": np.mean(times),
            "std_time_ms": np.std(times),
            "min_time_ms": np.min(times),
            "max_time_ms": np.max(times),
            "median_time_ms": np.median(times),
            "p95_time_ms": np.percentile(times, 95),
            "p99_time_ms": np.percentile(times, 99)
        }

    def reset_timing_stats(self):
        self.inference_times = []
        self.inference_count = 0

    def generate_performance_report(self):
        """Generate and log performance report"""
        stats = self.get_timing_stats()
        if not stats:
            if hasattr(settings, 'logger'):
                settings.logger.info("No timing data available for performance report")
            return
        
        report = (
            f"Kitsune Performance Summary:\n"
            f"  Total Inferences: {stats['total_inferences']}\n"
            f"  Average Time: {stats['avg_time_ms']:.3f}ms\n"
            f"  Median Time: {stats['median_time_ms']:.3f}ms\n"
            f"  95th Percentile: {stats['p95_time_ms']:.3f}ms\n"
            f"  99th Percentile: {stats['p99_time_ms']:.3f}ms\n"
            f"  Standard Deviation: {stats['std_time_ms']:.3f}ms"
        )
        if hasattr(settings, 'logger'):
            settings.logger.info(report)
        return stats

    def __del__(self):
        """Destructor to log final performance stats"""
        if (hasattr(self, 'inference_times') and 
            self.inference_times and 
            self.settings.get("performance_report_on_exit", True)):
            self.generate_performance_report()
