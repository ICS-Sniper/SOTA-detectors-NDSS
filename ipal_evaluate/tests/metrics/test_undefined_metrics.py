import numpy as np
import pytest

from metrics.affiliation import AffiliationMetric
from metrics.batadal import BatadalTTD
from metrics.metric import MetricNotApplicableError
from metrics.scenarios import AverageTimeToDetection


def test_batadal_ttd_without_ground_truth_is_not_applicable():
    dataset = [
        {"timestamp": 1, "malicious": False, "ids": False},
        {"timestamp": 2, "malicious": False, "ids": True},
    ]

    with pytest.raises(MetricNotApplicableError):
        BatadalTTD.calculate(dataset=dataset)


def test_affiliation_without_ground_truth_is_not_applicable():
    truth = np.array([False, False])
    predicted = np.array([False, True])

    with pytest.raises(MetricNotApplicableError):
        AffiliationMetric.calculate(truth=truth, predicted=predicted)


def test_average_ttd_without_detected_scenarios_is_nan():
    attacks = [{"id": "1", "start": 1, "end": 2}]

    result = AverageTimeToDetection.calculate(
        dataset=[], attacks=attacks, ergs={"Detected-Scenarios": []}
    )

    assert np.isnan(result["Average-Time-to-Detection"])
