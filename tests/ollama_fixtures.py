"""Synthetic local model metadata for existing provider-boundary tests."""
import json


def transport(status, raw):
    def send(base, path, **kwargs):
        if path == '/api/tags':
            return 200, {}, json.dumps({'models': [{'name': name} for name in ('fixture','fixture-model','test-model')]}).encode()
        if path == '/api/show':
            return 200, {}, b'{"details":{"format":"gguf"}}'
        return status, {}, raw
    return send


def envelope(content):
    return json.dumps({'done': True, 'done_reason': 'stop',
                       'message': {'role': 'assistant', 'content': content}}).encode()
