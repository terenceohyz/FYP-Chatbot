import os
import json
import sqlite3
import time
from flask import Flask, render_template, request, session, jsonify, redirect, url_for, abort
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode
from langchain_community.llms import CTransformers
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.messages import HumanMessage, AIMessage
from db import init_db_command
from user import User
from dotenv import load_dotenv
from models import ChatSession, Message
load_dotenv()

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# Configuration
GOOGLE_CLIENT_ID = os.getenv("OAUTH_GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("OAUTH_GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# User session management setup
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    pass

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Local LLM configuration
local_llm = "zephyr-7b-alpha.Q4_K_S.gguf"
config = {
    'context_length': 512,
    'max_new_tokens': 256,
    'repetition_penalty': 1.1,
    'temperature': 0.7,
    'top_k': 50,
    'top_p': 0.9,
    'threads': int(os.cpu_count() / 2),
}
llm_init = CTransformers(
    model=local_llm,
    model_type="mistral",
    lib="avx2",
    config=config
)

template = """You are a medical chatbot, answer the new question directly and if you don't have an answer, just say that you don't know.

Previous interaction: {history}

New Question: {question}
Answer: 
"""

def get_memory():
    if 'history' not in session:
        session['history'] = []
        initial_message = "Hello! How can I help you today? Please provide me with your symptoms or concerns."
        session['history'].append({'type': 'ai', 'content': initial_message})
    memory = ConversationBufferWindowMemory(return_messages=True, memory_key="history", k=1)
    for message in session['history']:
        if message['type'] == 'user':
            memory.chat_memory.add_message(HumanMessage(content=message['content']))
        else:
            memory.chat_memory.add_message(AIMessage(content=message['content']))
    return memory

def save_memory(memory):
    session['history'] = [{'type': 'user', 'content': msg.content} if isinstance(msg, HumanMessage) else {'type': 'ai', 'content': msg.content} for msg in memory.chat_memory.messages]

def get_public_key():
    with open("receiver.pem", 'rb') as key_binary:
        key = RSA.import_key(key_binary.read())
    return key.public_key().export_key()

def get_private_key():
    with open("private.pem", 'rb') as key_binary:
        key = RSA.import_key(key_binary.read())
    return key

def decrypt_data(encrypted_value):
    encrypted_data = json.loads(encrypted_value)
    encrypted_aes_key = b64decode(encrypted_data['encrypted_aes_key'])
    iv = b64decode(encrypted_data['iv'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    tag = b64decode(encrypted_data['tag'])

    private_key = get_private_key()
    rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    aes_cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    plain_text = aes_cipher.decrypt_and_verify(ciphertext, tag)

    return plain_text.decode()

def encrypt_data(plain_text):
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    aes_cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plain_text.encode())

    public_key = RSA.import_key(get_public_key())
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    encrypted_data = {
        'encrypted_aes_key': b64encode(encrypted_aes_key).decode(),
        'iv': b64encode(iv).decode(),
        'ciphertext': b64encode(ciphertext).decode(),
        'tag': b64encode(tag).decode()
    }

    return json.dumps(encrypted_data)

@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User(id_=unique_id, name=users_name, email=users_email, profile_pic=picture)

    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    login_user(user)
    return redirect(url_for("chat"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/new_chat', methods=['POST'])
@login_required
def new_chat():
    chat_id = ChatSession.create(current_user.id, title="New Chat")
    return jsonify(success=True, chat_id=chat_id)

@app.route('/get_chats', methods=['GET'])
@login_required
def get_chats():
    chats = ChatSession.get_all_for_user(current_user.id)
    chat_list = [{'id': chat['id'], 'title': chat['title'] or 'Untitled Chat'} for chat in chats]
    print(f"Chat list being sent to client: {chat_list}")
    return jsonify(chat_list)

@app.route('/delete_chat', methods=['POST'])
@login_required
def delete_chat():
    data = request.get_json()
    chat_id = data.get('chat_id')
    chat_session = ChatSession.get(chat_id)
    if chat_session and chat_session['user_id'] == current_user.id:
        ChatSession.delete(chat_id)
        return jsonify(success=True)
    else:
        return jsonify(success=False), 403

@app.route('/', methods=['GET', 'POST'])
@login_required
def chat():
    chat_id = request.args.get('chat_id')
    if not chat_id:
        # Start a new chat session
        chat_id = ChatSession.create(current_user.id, title="New Chat")
        return redirect(url_for('chat', chat_id=chat_id))

    # Get the chat session
    chat_session = ChatSession.get(chat_id)
    if not chat_session or chat_session['user_id'] != current_user.id:
        # Invalid chat session or not owned by current user
        return redirect(url_for('chat'))

    # Load messages for this chat session
    messages = Message.get_all_for_chat(chat_id)
    print(f"Messages retrieved for chat_id {chat_id}: {messages}")
    
    # Build memory from messages
    memory = ConversationBufferWindowMemory(return_messages=True, memory_key="history", k=1)
    for msg in messages:
        if msg['sender'] == 'user':
            memory.chat_memory.add_message(HumanMessage(content=msg['content']))
        else:
            memory.chat_memory.add_message(AIMessage(content=msg['content']))

    prompt = PromptTemplate(template=template, input_variables=["history", "question"])
    llm_chain = LLMChain(prompt=prompt, llm=llm_init, verbose=True, memory=memory)

    if request.method == 'GET':
        return render_template('chat.html', chat=messages, chat_id=chat_id, key=get_public_key().decode())

    elif request.method == 'POST':
        user_message = request.json.get('msg')
        print(user_message)
        text = decrypt_data(user_message)
        memory.chat_memory.add_message(HumanMessage(content=text))
        Message.create(chat_id, 'user', text)
        if chat_session['title'] == 'New Chat' or not chat_session['title']:
            truncated_text = text[:30] + ('...' if len(text) > 30 else '')
            ChatSession.update_title(chat_id, truncated_text)

        try:
            response = llm_chain.invoke({
                "history": memory.buffer,
                "question": text
            })
            response_text = response if isinstance(response, str) else response['text']
            memory.chat_memory.add_message(AIMessage(content=response_text))
            Message.create(chat_id, 'ai', response_text)
            encrypted_response = encrypt_data(response_text)
            return jsonify({
                'from': 'MediBot',
                'msg': encrypted_response,
                'time': str(round(time.time()*1000))
            })
        except Exception as e:
            return jsonify({
                'from': 'MediBot',
                'msg': str(e),
                'time': str(round(time.time()*1000))
            }), 500

    return render_template('chat.html', chat=memory.buffer)
 
if __name__ == '__main__':
    app.run(debug=True)