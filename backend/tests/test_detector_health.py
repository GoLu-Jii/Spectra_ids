from backend.app.config.detectors import DETECTOR_CONFIGS
from backend.app.detectors.health import unavailable_health


def test_health_state_reporting():
    config = DETECTOR_CONFIGS["dga"]
    health = unavailable_health(
        config,
        registered=True,
        dependency_available=True,
        error_reason="Artifact load failed: input stream corrupted",
    )

    assert health.detector_name == "dga"
    assert health.registered is True
    assert health.artifact_present is False
    assert health.artifact_loadable is False
    assert health.dependency_available is True
    assert health.ready_for_inference is False
    assert "corrupted" in health.error_reason
    assert health.as_dict()["ready_for_inference"] is False


def test_current_handoff_configuration_is_explicit():
    assert DETECTOR_CONFIGS["ddos"].handoff_status == "READY FOR BACKEND INTEGRATION"
    assert DETECTOR_CONFIGS["dga"].handoff_status == "BLOCKED"
    assert DETECTOR_CONFIGS["quic"].artifact_path is None
    assert DETECTOR_CONFIGS["quic"].handoff_status == "BLOCKED"
