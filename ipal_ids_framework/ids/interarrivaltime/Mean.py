import numpy as np
import time  # Add timing module
import orjson

import ipal_iids.settings as settings
from ids.ids import MetaIDS

# This is an implementation of the two IDSs proposed in:
#
#    Lin, Chih-Yuan, Simin Nadjm-Tehrani, and Mikael Asplund. "Timing-based
#    anomaly detection in SCADA networks." International Conference on
#    Critical Information Infrastructures Security. Springer, Cham, 2017.
#
# Look into that paper to understand what is going on here


class InterArrivalTimeMean(MetaIDS):
    _name = "InterArrivalTimeMean"
    _description = "Mean inter-arrival time"
    _requires = ["train.ipal", "live.ipal"]
    _interarrivaltimemean_default_settings = {
        "N": 4, 
        "W": 5, 
        "alert_unknown": True,
        "enable_timing": False,  # Add timing switch
        "timing_log_interval": 100,  # Log basic stats every 100 inferences
        "timing_detailed_interval": 1000,  # Log detailed stats every 1000 inferences
        "performance_report_on_exit": True,  # Generate performance report on exit
    }
    _supports_preprocessor = False

    def __init__(self, name=None):
        super().__init__(name=name)
        self._add_default_settings(self._interarrivaltimemean_default_settings)

        self.mean_model = {}
        self.sliding_windows = {}
        self._first_alert_logged = False
        
        # Timing related variables
        self.inference_times = []
        self.inference_count = 0

    def _log_first_alert(self, msg, reason, identifier=None, deviation=None, bounds=None):
        if self._first_alert_logged:
            return

        if hasattr(settings, "logger"):
            bound_text = ""
            if bounds is not None:
                bound_text = f" ll={bounds.get('ll')} ul={bounds.get('ul')}"

            settings.logger.info(
                "InterArrivalTimeMean first alert: "
                f"timestamp={msg.get('timestamp')} reason={reason} "
                f"identifier={identifier} deviation={deviation}{bound_text}"
                f"state={msg.get('data', {})}"
                f"maclicisou={msg.get('malicious', False)}"
            )

        # self._first_alert_logged = True

    def _get_identifier(self, msg):
        # Compute event identifier by concatenating source, destination, activity, message type and accessed data
        identifier = [
            msg["src"].split(":")[0],
            msg["dest"].split(":")[0],
            msg["activity"],
            str(msg["type"]),
        ]
        identifier += msg["data"].keys()
        return "-".join([str(i) for i in identifier])

    def train(self, ipal=None, state=None):
        events = {}

        # Load timestamps for each identifier
        with self._open_file(ipal) as f:
            for line in f:
                ipal_msg = orjson.loads(line)

                timestamp = ipal_msg["timestamp"]
                identifier = self._get_identifier(ipal_msg)

                if identifier not in events:
                    events[identifier] = []
                events[identifier].append(timestamp)

        # Calculate inter-arrival time and mean model
        settings.logger.info("Inter-arrival-time mean models:")

        for k in events.keys():
            interevent_times = []

            for i in range(len(events[k]) - 1):
                interevent_times.append(events[k][i + 1] - events[k][i])

            if len(interevent_times) <= self.settings["W"]:
                settings.logger.warning(f"Only single window of type {k}")
                continue

            mu = np.mean(interevent_times)
            sigma = np.std(interevent_times)

            ul = mu + self.settings["N"] * sigma
            ll = mu - self.settings["N"] * sigma
            ll = max(0, ll)  # Only positive inter-arrival times

            self.mean_model[k] = {
                "ll": float(ll),
                "ul": float(ul),
                "mu": float(mu),
                "sigma": float(sigma),
            }
            self.sliding_windows[k] = {
                "timestamp": [],
                "malicious": [],
                "interevents": [],
            }

            settings.logger.info(f"- {k} [{ll}, {ul}] mean: {mu} sigma: {sigma}")
        
        # Reset timing stats after training
        self.reset_timing_stats()
        settings.logger.info("InterArrivalTimeMean training completed. Timing statistics reset for live inference.")

    def new_ipal_msg(self, msg):
        # Start timing
        if self.settings.get("enable_timing", True):
            start_time = time.perf_counter()
        
        identifier = self._get_identifier(msg)

        if identifier not in self.sliding_windows:  # Unknown message
            result = self.settings["alert_unknown"], None
            if result[0]:
                self._log_first_alert(
                    msg,
                    "unknown_message",
                    identifier=identifier,
                    deviation=None,
                )

        else:  # Known message
            # Slide window
            if len(self.sliding_windows[identifier]["timestamp"]) == self.settings["W"]:
                del self.sliding_windows[identifier]["timestamp"][0]
                del self.sliding_windows[identifier]["malicious"][0]
                del self.sliding_windows[identifier]["interevents"][0]

            # Calculate inter-event time for last message
            if len(self.sliding_windows[identifier]["timestamp"]) > 0:
                intereventtime = (
                    msg["timestamp"] - self.sliding_windows[identifier]["timestamp"][-1]
                )
                self.sliding_windows[identifier]["interevents"].append(intereventtime)

            # Fill sliding window
            self.sliding_windows[identifier]["timestamp"].append(msg["timestamp"])
            self.sliding_windows[identifier]["malicious"].append(msg["malicious"])

            # Reached desired window size?
            if len(self.sliding_windows[identifier]["timestamp"]) < self.settings["W"]:
                result = False, 0
            else:
                assert (
                    len(self.sliding_windows[identifier]["interevents"])
                    == self.settings["W"] - 1
                )

                # Check mean model
                iet_mean = np.mean(self.sliding_windows[identifier]["interevents"])
                alert = not (
                    self.mean_model[identifier]["ll"]
                    <= iet_mean
                    <= self.mean_model[identifier]["ul"]
                )

                result = alert, iet_mean - self.mean_model[identifier]["mu"]
                if alert:
                    self._log_first_alert(
                        msg,
                        "out_of_mean_range",
                        identifier=identifier,
                        deviation=float(result[1]),
                        bounds={
                            "ll": self.mean_model[identifier]["ll"],
                            "ul": self.mean_model[identifier]["ul"],
                        },
                    )

        # End timing and comprehensive logging
        if self.settings.get("enable_timing", True):
            end_time = time.perf_counter()
            inference_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            self.inference_times.append(inference_time)
            self.inference_count += 1
            
            # Basic periodic logging
            log_interval = self.settings.get("timing_log_interval", 100)
            if self.inference_count % log_interval == 0:
                recent_times = self.inference_times[-log_interval:]
                avg_time = sum(recent_times) / len(recent_times)
                min_time = min(recent_times)
                max_time = max(recent_times)
                
                settings.logger.info(
                    f"InterArrivalTimeMean Timing (last {log_interval}): "
                    f"Avg={avg_time:.3f}ms, Min={min_time:.3f}ms, Max={max_time:.3f}ms"
                )
            
            # Detailed statistics logging
            detailed_interval = self.settings.get("timing_detailed_interval", 1000)
            if self.inference_count % detailed_interval == 0:
                stats = self.get_timing_stats()  # Actual call point!
                if stats:
                    settings.logger.info(
                        f"InterArrivalTimeMean Detailed Performance (n={stats['total_inferences']}): "
                        f"Median={stats['median_time_ms']:.3f}ms, "
                        f"P95={stats['p95_time_ms']:.3f}ms, "
                        f"P99={stats['p99_time_ms']:.3f}ms, "
                        f"Std={stats['std_time_ms']:.3f}ms"
                    )

        return result

    def get_timing_stats(self):
        """Get timing statistics"""
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
        """Reset timing statistics"""
        self.inference_times = []
        self.inference_count = 0

    def generate_performance_report(self):
        """Generate and log performance report"""
        stats = self.get_timing_stats()
        if not stats:
            settings.logger.info("No timing data available for performance report")
            return
        
        report = (
            f"InterArrivalTimeMean Performance Summary:\n"
            f"  Total Inferences: {stats['total_inferences']}\n"
            f"  Average Time: {stats['avg_time_ms']:.3f}ms\n"
            f"  Median Time: {stats['median_time_ms']:.3f}ms\n"
            f"  95th Percentile: {stats['p95_time_ms']:.3f}ms\n"
            f"  99th Percentile: {stats['p99_time_ms']:.3f}ms\n"
            f"  Standard Deviation: {stats['std_time_ms']:.3f}ms"
        )
        settings.logger.info(report)
        return stats

    def __del__(self):
        """Destructor to log final performance stats"""
        if (hasattr(self, 'inference_times') and 
            self.inference_times and 
            self.settings.get("performance_report_on_exit", True)):
            self.generate_performance_report()

    def save_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        model = {
            "_name": self._name,
            "settings": self.settings,
            "mean_model": self.mean_model,
        }

        with self._open_file(self._resolve_model_file_path(), mode="wb") as f:
            f.write(orjson.dumps(model) + b"\n")

        return True

    def load_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        try:  # Open model file
            with self._open_file(self._resolve_model_file_path(), mode="rb") as f:
                model = orjson.loads(f.read())
        except FileNotFoundError:
            settings.logger.info(
                f"Model file {str(self._resolve_model_file_path())} not found."
            )
            return False

        # Load model
        assert self._name == model["_name"]
        self.settings = model["settings"]
        self.mean_model = model["mean_model"]

        for k in model["mean_model"].keys():
            self.sliding_windows[k] = {
                "timestamp": [],
                "malicious": [],
                "interevents": [],
            }

        return True

    def visualize_model(self):
        import matplotlib.pyplot as plt
        import numpy as np

        fig, ax = plt.subplots(1)

        xs = np.arange(len(self.mean_model))
        labels = [x for x in self.mean_model]
        mins = np.array([self.mean_model[label]["ll"] for label in labels])
        maxs = np.array([self.mean_model[label]["ul"] for label in labels])
        means = np.array([self.mean_model[label]["mu"] for label in labels])
        stds = np.array([self.mean_model[label]["sigma"] for label in labels])

        ax.errorbar(
            xs,
            means,
            [means - mins, maxs - means],
            fmt=".k",
            ecolor="gray",
            lw=1,
            zorder=2,
        )
        ax.errorbar(xs, means, stds, fmt="ok", lw=3, zorder=1)

        ax.set_xticks(xs)
        ax.set_xticklabels(labels, rotation=90, ha="center")

        ax.set_ylabel("Inter arrival time [in s]")
        ax.set_title(f"N: {self.settings['N']} W: {self.settings['W']}")

        return plt, fig
