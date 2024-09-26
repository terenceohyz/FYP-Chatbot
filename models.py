from db import get_db

class ChatSession:
    @staticmethod
    def create(user_id, title):
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO chat_session (user_id, title) VALUES (?, ?)",
            (user_id, title)
        )
        db.commit()
        print(f"Created chat_session with id {cursor.lastrowid} and title '{title}'")
        return cursor.lastrowid

    @staticmethod
    def get_all_for_user(user_id):
        db = get_db()
        chats = db.execute(
            "SELECT * FROM chat_session WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()
        return chats

    @staticmethod
    def get(chat_id):
        db = get_db()
        chat = db.execute(
            "SELECT * FROM chat_session WHERE id = ?",
            (chat_id,)
        ).fetchone()
        return chat

    @staticmethod
    def update_title(chat_id, title):
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "UPDATE chat_session SET title = ? WHERE id = ?",
            (title, chat_id)
        )
        db.commit()
        print(f"Updated chat_session id {chat_id} with title '{title}'")

    @staticmethod
    def delete(chat_id):
        db = get_db()
        # Delete messages associated with the chat session
        db.execute(
            "DELETE FROM message WHERE chat_id = ?",
            (chat_id,)
        )
        # Delete the chat session
        db.execute(
            "DELETE FROM chat_session WHERE id = ?",
            (chat_id,)
        )
        db.commit()

class Message:
    @staticmethod
    def create(chat_id, sender, content):
        db = get_db()
        db.execute(
            "INSERT INTO message (chat_id, sender, content) VALUES (?, ?, ?)",
            (chat_id, sender, content)
        )
        db.commit()

    @staticmethod
    def get_all_for_chat(chat_id):
        db = get_db()
        messages = db.execute(
            "SELECT * FROM message WHERE chat_id = ? ORDER BY created_at ASC",
            (chat_id,)
        ).fetchall()
        return messages
