"""Bounded output buffers and explicit nested Arrow types (layout version 2)."""
import json


def arrow_schema(keys):
    import pyarrow as pa
    text = pa.string()
    integer = pa.int64()
    strings = pa.list_(text)
    structs = {
        'ioc_matches': pa.list_(pa.struct([(key, text) for key in ('type', 'value', 'matched_field', 'source', 'fetched_at', 'expires_at')])),
        'semantic_evidence': pa.struct([(key, text) for key in ('request_body', 'message', 'user_agent')]),
        'raw_reference': pa.struct([('source_file', text), ('row', integer)]),
        'data_quality': pa.struct([('timestamp_parse_error', pa.bool_())]),
        'score_components': pa.struct([(key, integer) for key in ('rule_or_ioc', 'session_frequency', 'source_activity', 'asset_criticality')]),
        'evidence_reference': pa.struct([('event_id', text), ('batch_id', text)]),
        'evidence': pa.list_(pa.struct([(key, text) for key in ('type', 'name', 'rule_version', 'source', 'severity', 'threat_type')] + [('judgments', strings)] + [(key, integer) for key in ('unique_path_count', 'window_seconds', 'min_unique_paths', 'min_sensitive_paths')])),
    }
    lists = {'rule_hits', 'related_event_ids', 'related_session_ids', 'targets', 'sample_paths', 'behavior_tags', 'reasoning', 'domains', 'paths', 'tactic_candidates'}
    numbers = {'source_row', 'src_port', 'dst_port', 'risk_score', 'event_count', 'source_session_count', 'session_count', 'target_count', 'unique_path_count', 'domains_count', 'paths_count'}
    numbers.add('source_count')
    return pa.schema([(key, structs[key] if key in structs else strings if key in lists else integer if key in numbers else pa.float64() if key == 'confidence' else pa.bool_() if key in ('detail_available', 'source_identity_shared', 'path_count_is_lower_bound') else text) for key in keys])


class EventWriter:
    def __init__(self, ready, name, output):
        self.parquet = output.get('format', 'parquet') == 'parquet'
        self.batch_size = int(output.get('batch_size', 1000))
        self.byte_limit = int(output.get('batch_bytes', 8 * 1024 * 1024))
        if self.batch_size < 1 or self.byte_limit < 1:
            raise ValueError('output batch_size and batch_bytes must be positive')
        if self.parquet:
            import pyarrow.parquet  # Fail before processing, never silently change format.
        self.path = ready / (name + ('.parquet' if self.parquet else '.jsonl'))
        self.name = name
        self.buffer = []
        self.bytes = 0
        self.writer = None
        self.schema = None

    def append(self, row):
        self.buffer.append(row)
        # Approximate UTF-8 capacity without serializing payloads to JSON.
        self.bytes += sum(len(value) * 4 for value in row.values() if isinstance(value, str))
        if len(self.buffer) >= self.batch_size or self.bytes >= self.byte_limit:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        if self.parquet:
            import pyarrow as pa
            import pyarrow.parquet as pq
            if self.writer is None:
                self.schema = arrow_schema(self.buffer[0].keys())
                self.writer = pq.ParquetWriter(self.path, self.schema, compression='snappy')
            self.writer.write_table(pa.Table.from_pylist(self.buffer, schema=self.schema))
        else:
            if self.writer is None:
                self.writer = self.path.open('w', encoding='utf-8')
            self.writer.writelines(json.dumps(row, ensure_ascii=False, default=str) + '\n' for row in self.buffer)
        self.buffer.clear()
        self.bytes = 0

    def close(self):
        try:
            self.flush()
            if self.writer is None:
                if self.parquet:
                    import pyarrow as pa
                    import pyarrow.parquet as pq
                    keys = ['event_id']
                    if self.name in ('all_sessions', 'suspicious_events', 'l3_candidates'):
                        keys = ['event_id', 'batch_id', 'session_id', 'session_fingerprint', 'fingerprint_version', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'first_seen', 'last_seen', 'victim_asset_id', 'source_role', 'direction', 'source_identity_shared', 'domains', 'paths', 'domains_count', 'paths_count', 'ioc_matches', 'tactic_candidates', 'rule_hits', 'risk_score', 'risk_level', 'event_count', 'related_event_ids', 'semantic_status']
                    pq.write_table(pa.Table.from_pylist([], schema=arrow_schema(keys)), self.path)
                else:
                    self.path.touch()
        finally:
            if self.writer is not None:
                self.writer.close()

    def abort(self):
        self.buffer.clear()
        if self.writer is not None:
            self.writer.close()
