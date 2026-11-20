"""Helpers for tests that run a full analysis with the AI call replaced:
run() returns the exact prompt the provider would receive and the result."""
import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from secret_detection import MECHANISMS

OFF = {name: False for name in MECHANISMS}

def privacy(pattern, mode='full_value'):
    return dict(id='test-privacy', pattern=pattern, action='hide_privacy',
                mode=mode, scope='all', capture_group=0, enabled=True)

def log_block(prompt):
    return prompt.split('Security Logs:\n```json\n', 1)[1].split('\n```', 1)[0]

def run(logs, *, rules=(), feedback=(), reply='ok', config=None, **options):
    sent=[]
    async def ai(prompt, key):
        sent.append(prompt)
        return reply(prompt) if callable(reply) else reply
    req=server.LogAnalysisRequest(logs=logs, mode='groq', api_key='synthetic',
        sanitize=options.pop('sanitize',False), custom_regex_rules=list(rules),
        secret_protection=config if config is not None else {}, **options)
    with patch.object(server,'call_groq_ai',ai), patch.object(server,'training_data',
         {'feedback_entries':[{'user_correction':v, 'status':'approved'} for v in feedback]}):
        result=asyncio.run(server.analyze_logs(req))
    return sent[0],result
