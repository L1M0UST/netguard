"""De-duplication and normalisation tests."""

from __future__ import annotations

from datetime import timedelta

from backend.module2_chain.ingestion.deduplicator import EventDeduplicator
from backend.module2_chain.ingestion.normalizer import EventNormalizer
from backend.module2_chain.tests.conftest import BASE_TIME, make_event


def test_duplicate_event_ids_are_dropped(config) -> None:
    events = [
        make_event("evt_1"),
        make_event("evt_1"),
        make_event("evt_2", dst_port=443),
    ]
    result = EventDeduplicator(config).deduplicate(events)
    assert result.input_count == 3
    assert result.output_count == 2
    assert result.duplicate_event_id_count == 1
    assert result.duplicate_event_ids == ["evt_1"]


def test_content_duplicates_are_dropped_and_best_score_kept(config) -> None:
    events = [
        make_event("evt_1", score=40.0, payload_digest="fixed"),
        make_event("evt_2", score=90.0, payload_digest="fixed"),
        make_event("evt_3", score=10.0, payload_digest="fixed"),
    ]
    result = EventDeduplicator(config).deduplicate(events)
    assert result.output_count == 1
    assert result.content_duplicate_count == 2
    assert result.events[0].detection.score == 90.0


def test_events_outside_the_time_bucket_are_not_collapsed(config) -> None:
    late = BASE_TIME + timedelta(seconds=config.dedup.content_hash_time_bucket_seconds * 3)
    events = [
        make_event("evt_1", payload_digest="fixed"),
        make_event("evt_2", timestamp=late, payload_digest="fixed"),
    ]
    result = EventDeduplicator(config).deduplicate(events)
    assert result.output_count == 2


def test_distinct_rules_are_not_collapsed(config) -> None:
    events = [
        make_event("evt_1", rules=["l1_a"], payload_digest="fixed"),
        make_event("evt_2", rules=["l1_b"], payload_digest="fixed"),
    ]
    assert EventDeduplicator(config).deduplicate(events).output_count == 2


def test_empty_input_is_handled(config) -> None:
    result = EventDeduplicator(config).deduplicate([])
    assert result.output_count == 0
    assert result.dropped_count == 0


def test_normalizer_canonicalises_ips_and_protocols(config) -> None:
    events = [
        make_event("evt_1", src_ip="::ffff:10.0.0.8", dst_ip=" 10.0.0.12 ", protocol="TCP"),
        make_event("evt_2", src_ip="2001:0db8::0001", dst_ip="10.0.0.13", protocol="UDP"),
    ]
    result = EventNormalizer(config).normalize(events)
    assert result.ip_changes == 2
    # The schema validator already lowercases protocols, so the normaliser has
    # nothing left to do for them - that is the expected, idempotent behaviour.
    assert result.protocol_changes == 0
    assert result.events[0].event.src_ip == "10.0.0.8"
    assert result.events[0].event.dst_ip == "10.0.0.12"
    assert result.events[0].event.protocol == "tcp"
    assert result.events[1].event.src_ip == "2001:db8::1"


def test_normalizer_strips_whitespace_from_identifiers(config) -> None:
    event = make_event("evt_1")
    event.event.event_id = "  evt_1  "
    event.detection.matched_rules = [" l1_rule ", ""]
    result = EventNormalizer(config).normalize([event])
    assert result.events[0].event.event_id == "evt_1"
    assert result.events[0].detection.matched_rules == ["l1_rule"]


def test_normalizer_handles_empty_list(config) -> None:
    assert EventNormalizer(config).normalize([]).events == []
