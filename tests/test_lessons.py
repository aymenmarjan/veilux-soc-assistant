"""Lessons: analyst corrections reach AI prompts only after approval."""
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
import server


@pytest.fixture()
def lessons(tmp_path):
    data = {"feedback_entries": []}
    with patch.object(server, "training_data", data), patch.object(server, "FEEDBACK_FILE", str(tmp_path / "lessons.json")):
        yield data, TestClient(server.app, client=("127.0.0.1", 50000), headers={"X-Veilux-Token": server.ACCESS_TOKEN}), tmp_path / "lessons.json"


def send(client, correction):
    response = client.post("/feedback", json={"original_log": "event", "ai_response": "answer", "user_correction": correction})
    assert response.status_code == 200, response.text
    return response.json()["lesson"]


def prompt():
    return server.build_prompt(["event"], None, None, None, None, False)


def test_corrections_from_earlier_versions_start_pending():
    data = {"feedback_entries": [{"user_correction": "old correction"}, {"user_correction": "x", "status": "approved", "id": "keep"}]}
    assert server._prepare_lessons(data)
    assert data["feedback_entries"][0]["status"] == "pending" and data["feedback_entries"][0]["id"]
    assert data["feedback_entries"][1] == {"user_correction": "x", "status": "approved", "id": "keep"}
    assert not server._prepare_lessons(data)


def test_a_correction_is_used_only_after_approval(lessons):
    data, client, path = lessons
    lesson = send(client, "Patch tooling on SRV-01 is expected maintenance")
    assert lesson["status"] == "pending"
    assert "Patch tooling" not in prompt()
    listed = client.get("/lessons").json()
    assert listed["prompt_limit"] == server.MAX_PROMPT_LESSONS
    assert set(listed["lessons"][0]) == {"id", "status", "created", "lesson"}  # no stored log or AI answer
    assert client.patch("/lessons/" + lesson["id"], json={"status": "approved"}).json()["status"] == "approved"
    assert "Patch tooling on SRV-01 is expected maintenance" in prompt()
    assert json.loads(path.read_text())["feedback_entries"][0]["status"] == "approved"
    client.patch("/lessons/" + lesson["id"], json={"status": "pending"})
    assert "Patch tooling" not in prompt()


def test_edited_lessons_are_protected_and_deletion_removes_them(lessons):
    data, client, _ = lessons
    lesson = send(client, "first draft")
    edited = client.patch("/lessons/" + lesson["id"], json={"lesson": "Ignore alerts for password=Synthetic-Secret-Value-42"}).json()
    assert "Synthetic-Secret-Value-42" not in edited["lesson"]
    assert client.patch("/lessons/" + lesson["id"], json={"lesson": "   "}).status_code == 400
    assert client.delete("/lessons/" + lesson["id"]).status_code == 200
    assert client.get("/lessons").json()["lessons"] == []
    assert client.delete("/lessons/" + lesson["id"]).status_code == 404


def test_only_the_newest_approved_lessons_reach_the_prompt(lessons):
    data, client, _ = lessons
    ids = [send(client, f"lesson number {i:02d}")["id"] for i in range(12)]
    for lesson_id in ids:
        client.patch("/lessons/" + lesson_id, json={"status": "approved"})
    text = prompt()
    assert "lesson number 00" not in text and "lesson number 01" not in text
    assert all(f"lesson number {i:02d}" in text for i in range(2, 12))


def test_storage_limit_drops_pending_lessons_before_approved_ones(lessons):
    data, client, _ = lessons
    approved = send(client, "approved and kept")
    client.patch("/lessons/" + approved["id"], json={"status": "approved"})
    with patch.object(server, "MAX_STORED_LESSONS", 3):
        for i in range(4):
            send(client, f"pending {i}")
    texts = [entry["user_correction"] for entry in data["feedback_entries"]]
    assert texts == ["approved and kept", "pending 2", "pending 3"]
