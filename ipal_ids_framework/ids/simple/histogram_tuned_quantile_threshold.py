import json
import numpy as np

import ipal_iids.settings as settings
from ids.featureids import FeatureIDS
from ipal_iids.alerts import raise_alert, withdraw_alert


class Histogram(FeatureIDS):
    _name = "Histogram"
    _description = "Histogram-based anomaly detection with calibrated threshold."

    _requires = ["train.ipal", "live.ipal", "train.state", "live.state"]

    _histogram_default_settings = {
        "window_size": 100,
        "threshold": 1.0,              # scaling factor inside histogram
        "decision_threshold": 1.0,     # final anomaly decision threshold
        "quantile": 0.999,            # for automatic calibration
        "discrete_threshold": 10,
        "min_decision_threshold": 1.0,
        "decision_threshold_margin": 0.05,
        "calibration_mad_scale": 2.0,
        "unknown_consecutive_threshold": 3,
        "unknown_penalty": 0.6,
    }

    def __init__(self, name=None):
        super().__init__(name=name)
        self._add_default_settings(self._histogram_default_settings)

        self.hist = {}
        self.deltas = {}

        self._reset()

    def _reset(self):
        self._cur = {}
        self._buffer = {}
        self._unknown_streak = {}

    def _update(self, sensor, value):
        if sensor not in self._cur:
            self._cur[sensor] = {i: 0 for i in self.hist[sensor].keys()}
            self._buffer[sensor] = []

        self._cur[sensor][value] += 1
        self._buffer[sensor].append(value)

        if len(self._buffer[sensor]) > self.settings["window_size"]:
            self._cur[sensor][self._buffer[sensor].pop(0)] -= 1

        return len(self._buffer[sensor]) == self.settings["window_size"]

    def train(self, ipal=None, state=None):
        if ipal is not None and state is not None:
            settings.logger.warning("Only state OR ipal supported. Using state now.")
        elif state is None:
            state = ipal

        events, annotations, _ = super().train(state=state)

        if len(set(annotations) - {False}) > 0:
            settings.logger.warning("IDS expects benign data only!")

        # -------------------------------
        # Build histogram
        # -------------------------------
        hist = {}
        for i in range(len(events[0])):
            vals = set([e[i] for e in events])
            if len(vals) > self.settings["discrete_threshold"]:
                hist[i] = None
                self.hist[i] = None
                self.deltas[i] = None
            else:
                hist[i] = {val: [] for val in vals}
                self.hist[i] = {val: [self.settings["window_size"], 0] for val in vals}
                self.deltas[i] = {val: None for val in vals}

        for e in events:
            for i in range(len(events[0])):
                if self.hist[i] is None:
                    continue

                complete = self._update(i, e[i])
                if complete:
                    for val in self.hist[i]:
                        hist[i][val].append(self._cur[i][val])

        for i in range(len(events[0])):
            if self.hist[i] is None:
                settings.logger.info(f"Sensor {i} ignored")
                continue

            for val in self.hist[i]:
                self.hist[i][val] = [min(hist[i][val]), max(hist[i][val])]
                self.deltas[i][val] = (self.hist[i][val][1] - self.hist[i][val][0]) / 2

        # -------------------------------
        # Calibration phase (VERY IMPORTANT)
        # -------------------------------
        self._reset()
        calibration_scores = []

        for e in events:
            likelihood = 0
            window_ready = False

            for i in range(len(e)):
                if self.hist[i] is None:
                    continue

                complete = self._update(i, e[i])
                if not complete:
                    continue

                window_ready = True

                _, local_likelihood = self._is_valid(i)
                likelihood = max(likelihood, local_likelihood)

            # Exclude warm-up positions where no full window exists yet.
            if window_ready:
                calibration_scores.append(likelihood)

        if len(calibration_scores) > 0:
            q = self.settings.get("quantile", 0.999)
            q_value = float(np.quantile(calibration_scores, q))
            median = float(np.median(calibration_scores))
            mad = float(np.median(np.abs(np.array(calibration_scores) - median)))
            mad_scale = float(self.settings.get("calibration_mad_scale", 2.0))
            margin = float(self.settings.get("decision_threshold_margin", 0.05))
            min_threshold = float(self.settings.get("min_decision_threshold", 1.0))

            threshold = max(q_value + mad_scale * mad + margin, min_threshold)
            self.settings["decision_threshold"] = threshold

            settings.logger.info(
                f"[Histogram] decision_threshold={threshold:.6f} "
                f"(q={q}, q_value={q_value:.6f}, mad={mad:.6f})"
            )

            settings.logger.info(
                f"[Histogram] calibration stats: "
                f"p50={np.percentile(calibration_scores,50):.4f}, "
                f"p99={np.percentile(calibration_scores,99):.4f}, "
                f"max={max(calibration_scores):.4f}"
            )

        else:
            settings.logger.warning("No calibration scores collected!")

        self._reset()

    def _is_valid(self, sensor):
        likelihood = 0

        for val in self.hist[sensor]:
            tmin, tmax = self.hist[sensor][val]
            err = self.deltas[sensor][val] * self.settings["threshold"]
            cur = self._cur[sensor][val]

            if cur < tmin or tmax < cur:
                overshoot = abs(((tmax + tmin) * 0.5 - cur)) - (tmax - tmin) * 0.5
                likelihood = max(likelihood, overshoot / (1 if err == 0 else err))

            if cur < tmin - err or tmax + err < cur:
                return False, likelihood

        return True, likelihood

    def new_state_msg(self, msg):
        likelihood = 0
        alert = False

        state = super().new_state_msg(msg)
        if state is None:
            return alert, likelihood

        for i in range(len(state)):
            if self.hist[i] is None:
                continue

            sensor = self._get_feature_name(i).removeprefix("state;")

            if state[i] not in self.hist[i]:
                streak = self._unknown_streak.get(i, 0) + 1
                self._unknown_streak[i] = streak

                unknown_trigger = int(self.settings.get("unknown_consecutive_threshold", 3))
                if streak >= unknown_trigger:
                    base_penalty = float(self.settings.get("unknown_penalty", 0.6))
                    likelihood = max(likelihood, base_penalty + 0.1 * (streak - unknown_trigger))
                continue

            self._unknown_streak[i] = 0

            complete = self._update(i, state[i])
            if not complete:
                continue

            _, local_likelihood = self._is_valid(i)
            likelihood = max(likelihood, local_likelihood)

        # Debug（可注释掉）
        if likelihood > 0:
            settings.logger.debug(
                f"[Histogram DEBUG] ts={msg['timestamp']} likelihood={likelihood:.4f}"
            )

        threshold = self.settings.get("decision_threshold", 1.0)
        is_anomaly = likelihood > threshold
        alert = is_anomaly

        if is_anomaly:
            raise_alert(
                f"{self._name}",
                "global",
                msg["timestamp"],
                "Histogram anomaly detected",
                f"likelihood={likelihood:.4f} > threshold={threshold:.4f}",
            )
        else:
            withdraw_alert(
                f"{self._name}",
                "global",
                msg["timestamp"],
            )

        return alert, likelihood

    def new_ipal_msg(self, msg):
        return self.new_state_msg(msg)

    def save_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        model = {
            "_name": self._name,
            "preprocessors": super().save_trained_model(),
            "settings": self.settings,
            "hist": self.hist,
            "deltas": self.deltas,
        }

        with self._open_file(self._resolve_model_file_path(), "w") as f:
            f.write(json.dumps(model))

        return True

    def load_trained_model(self):
        if self.settings["model-file"] is None:
            return False

        try:
            with self._open_file(self._resolve_model_file_path(), "rt") as f:
                model = json.loads(f.read())
        except FileNotFoundError:
            settings.logger.info("Model file not found.")
            return False

        assert self._name == model["_name"]

        super().load_trained_model(model["preprocessors"])
        self.settings = model["settings"]
        self.hist = {int(k): v for k, v in model["hist"].items()}
        self.deltas = {int(k): v for k, v in model["deltas"].items()}

        self._reset()

        return True