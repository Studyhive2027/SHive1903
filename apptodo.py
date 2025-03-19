from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import random
import smtplib
from email.mime.text import MIMEText
from bson.objectid import ObjectId
from datetime import datetime
from room import room_bp, init_socketio

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management
socketio = SocketIO(app)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt

# Configure upload folder
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'avatars')
# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Configure allowed file extensions
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client["userDB"]
users_collection = db["users"]
todos_collection = db["todos"]
expenses_collection = db["expenses"]
messages_collection = db["messages"]
conversations_collection = db["conversations"]
rooms_collection = db["rooms"]
room_messages_collection = db["room_messages"]
room_tasks_collection = db["room_tasks"]

# Add new collections for tracking user details
study_sessions_collection = db["study_sessions"]
course_progress_collection = db["course_progress"]
performance_collection = db["performance"]
study_goals_collection = db["study_goals"]

# Initialize Socket.IO event handlers
init_socketio(socketio)

# Register room blueprint with a url_prefix to avoid conflicts
app.register_blueprint(room_bp, url_prefix='/study-rooms')

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data.get('email', '')
        self.full_name = user_data.get('full_name', '')
        self.bio = user_data.get('bio', '')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

# Home route
@app.route('/')
@login_required
def home():
    # Get user's todos
    todos = list(todos_collection.find({"user_id": ObjectId(current_user.id)}))
    
    # Get user's expenses
    expenses = list(expenses_collection.find({"user_id": ObjectId(current_user.id)}))
    
    # Get user's study sessions
    study_sessions = list(study_sessions_collection.find({"user_id": ObjectId(current_user.id)}))
    
    # Get user's course progress
    course_progress = list(course_progress_collection.find({"user_id": ObjectId(current_user.id)}))
    
    return render_template('home.html',
                         username=current_user.username,
                         todos=todos,
                         expenses=expenses,
                         study_sessions=study_sessions,
                         course_progress=course_progress)

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form.get('full_name', '')
        bio = request.form.get('bio', '')

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('signup'))
            
        if len(password) < 8:
            flash("Password must be at least 8 characters long!", "error")
            return redirect(url_for('signup'))

        if users_collection.find_one({"username": username}):
            flash("Username already exists!", "error")
            return redirect(url_for('signup'))
        if users_collection.find_one({'email': email}):
            flash("Email already exists!", "error")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert the new user
        user_data = {
            'email': email,
            "username": username,
            "password": hashed_password,
            "full_name": full_name,
            "bio": bio,
            "followers": [],
            "following": [],
            "profile_pic": None
        }
        result = users_collection.insert_one(user_data)
        
        # Get the inserted user and log them in
        user_data['_id'] = result.inserted_id
        user = User(user_data)
        login_user(user)
        session['username'] = username

        flash("Account created successfully! Welcome!", "success")
        return redirect(url_for('home'))

    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        # Check if the input is an email or username
        if '@' in username_or_email:
            user_data = users_collection.find_one({'email': username_or_email})
        else:
            user_data = users_collection.find_one({'username': username_or_email})

        # Verify user and password
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            session['username'] = user.username
            
            # Get the next parameter from the request
            next_page = request.args.get('next')
            # Validate the next parameter to prevent open redirect vulnerability
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('home'))
        else:
            flash("Invalid username/email or password!", "error")

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Forgot password route
@app.route("/forgotpassword", methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form['email']
        # Add logic to handle password reset (e.g., send an email)
        flash("Password reset link has been sent to your email.", "success")
        return redirect(url_for('login'))
    return render_template('forgotpassword.html')

# Store OTPs separately for signup and forgot password
signup_otp_storage = {}  
forgot_password_otp_storage = {}  

# Function to send OTP via email (Updated Subject for Signup)
def send_otp_email(email, otp, purpose):
    sender_email = "studyhive2027@gmail.com"
    sender_password = "prfi rqqg qyoo dyqf"

    subject = "Account Signup OTP" if purpose == "signup" else "Password Reset OTP"
    message = MIMEText(f"Your OTP for {purpose} is: {otp}")
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [email], message.as_string())
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data['email']

    # Check if the email exists in the database
    if not users_collection.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email not found.'})

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))
    forgot_password_otp_storage[email] = otp  # Store OTP for forgot password

    print(f"🔹 OTP for {email} (Forgot Password): {otp}")  # Debugging

    if send_otp_email(email, otp, "forgot password"):
        return jsonify({'success': True, 'otp': otp})  # Send OTP for debugging
    else:
        return jsonify({'success': False, 'message': 'Failed to send OTP.'})

# Route to reset password
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data['email']
    new_password = data['newPassword']
    entered_otp = data['otp']

    print(f"🔍 Verifying Forgot Password OTP for {email}. Expected: {forgot_password_otp_storage.get(email)}, Received: {entered_otp}")

    # Check if OTP matches
    if email not in forgot_password_otp_storage or forgot_password_otp_storage[email] != entered_otp:
        return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'})

    # Hash the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Update the user's password in the database
    users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})

    # Remove OTP after successful verification
    del forgot_password_otp_storage[email]

    return jsonify({'success': True})

# Route to add a new To-Do item
@app.route('/add_todo', methods=['POST'])
def add_todo():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    task = request.json.get('task')
    task_date = request.json.get('task_date')
    color = request.json.get('color', '#a4e1a1')  # Get color from request or use default
    
    # If task_date is not provided, use today's date
    if not task_date:
        from datetime import date
        task_date = date.today().strftime('%Y-%m-%d')

    if not task:
        return jsonify({'success': False, 'message': 'Task cannot be empty.'})

    # Insert the new task into the database
    todos_collection.insert_one({
        'username': username,
        'task': task,
        'task_date': task_date,
        'completed': False,
        'color': color  # Save the color in the database
    })

    return jsonify({'success': True})

# Route to get all To-Do items for the logged-in user
@app.route('/get_todos', methods=['GET'])
def get_todos():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    todos = list(todos_collection.find({'username': username}))

    # Convert ObjectId to string for JSON serialization
    for todo in todos:
        todo['_id'] = str(todo['_id'])
        # Ensure color property exists
        if 'color' not in todo:
            todo['color'] = '#a4e1a1'  # Default color

    # Debug log to check todos being returned
    print(f"Returning {len(todos)} todos for {username}")
    for todo in todos[:3]:  # Print first 3 for debugging
        print(f"Todo: {todo.get('task')}, Color: {todo.get('color')}")

    return jsonify({'success': True, 'todos': todos})

# Route to mark a To-Do item as completed
@app.route('/complete_todo', methods=['POST'])
def complete_todo():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    todo_id = request.json.get('todo_id')
    if not todo_id:
        return jsonify({'success': False, 'message': 'Todo ID is required.'})

    # Update the task as completed
    todos_collection.update_one({'_id': ObjectId(todo_id)}, {'$set': {'completed': True}})

    return jsonify({'success': True})

# Route to delete a To-Do item
@app.route('/delete_todo', methods=['POST'])
def delete_todo():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    todo_id = request.json.get('todo_id')
    if not todo_id:
        return jsonify({'success': False, 'message': 'Todo ID is required.'})

    # Delete the task
    todos_collection.delete_one({'_id': ObjectId(todo_id)})

    return jsonify({'success': True})

# Route to add a new expense
@app.route('/add_expense', methods=['POST'])
def add_expense():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    expense_name = request.json.get('expense_name')
    expense_amount = request.json.get('expense_amount')

    if not expense_name or not expense_amount:
        return jsonify({'success': False, 'message': 'Expense name and amount are required.'})

    # Insert the new expense into the database
    expenses_collection.insert_one({
        'username': username,
        'expense_name': expense_name,
        'expense_amount': float(expense_amount)
    })

    return jsonify({'success': True})

# Route to get all expenses for the logged-in user
@app.route('/get_expenses', methods=['GET'])
def get_expenses():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    expenses = list(expenses_collection.find({'username': username}))

    # Convert ObjectId to string for JSON serialization
    for expense in expenses:
        expense['_id'] = str(expense['_id'])

    return jsonify({'success': True, 'expenses': expenses})

# Route to delete an expense
@app.route('/delete_expense', methods=['POST'])
def delete_expense():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    expense_id = request.json.get('expense_id')
    if not expense_id:
        return jsonify({'success': False, 'message': 'Expense ID is required.'})

    # Delete the expense
    expenses_collection.delete_one({'_id': ObjectId(expense_id)})

    return jsonify({'success': True})

# Route to set or update total balance
@app.route('/set_balance', methods=['POST'])
def set_balance():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    new_balance = request.json.get('balance')

    if new_balance is None:
        return jsonify({'success': False, 'message': 'Balance amount is required.'})

    # Update or insert the balance in the database
    db.balances.update_one({'username': username}, {'$set': {'balance': float(new_balance)}}, upsert=True)

    return jsonify({'success': True, 'message': 'Balance updated successfully.'})

# Route to get the total balance
@app.route('/get_balance', methods=['GET'])
def get_balance():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    balance_data = db.balances.find_one({'username': username})

    balance = balance_data['balance'] if balance_data else 0  # Default to 0 if not set
    return jsonify({'success': True, 'balance': balance})

@app.route('/update_balance', methods=['POST'])
def update_balance():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    username = session['username']
    expense_name = request.json.get('expense_name')
    expense_amount = request.json.get('expense_amount')

    if not expense_name or expense_amount is None:
        return jsonify({'success': False, 'message': 'Expense name and amount are required.'})

    # Fetch current balance
    balance_data = db.balances.find_one({'username': username})
    current_balance = balance_data['balance'] if balance_data else 0

    # Ensure user cannot overspend
    if expense_amount > current_balance:
        return jsonify({'success': False, 'message': 'Insufficient balance.'})

    # Deduct expense from balance
    new_balance = current_balance - expense_amount

    # Update database
    db.expenses.insert_one({'username': username, 'expense_name': expense_name, 'expense_amount': float(expense_amount)})
    db.balances.update_one({'username': username}, {'$set': {'balance': new_balance}})

    return jsonify({'success': True, 'new_balance': new_balance})

# Route to delete an expense and restore balance
@app.route('/reset_balance', methods=['POST'])
def reset_balance():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})

    expense_id = request.json.get('expense_id')

    if not expense_id:
        return jsonify({'success': False, 'message': 'Expense ID is required.'})

    # Find the expense amount before deleting
    expense = db.expenses.find_one({'_id': ObjectId(expense_id)})

    if not expense:
        return jsonify({'success': False, 'message': 'Expense not found.'})

    expense_amount = expense['expense_amount']

    # Restore the balance
    balance_data = db.balances.find_one({'username': session['username']})
    current_balance = balance_data['balance'] if balance_data else 0
    new_balance = current_balance + expense_amount

    # Delete expense and update balance
    db.expenses.delete_one({'_id': ObjectId(expense_id)})
    db.balances.update_one({'username': session['username']}, {'$set': {'balance': new_balance}})

    return jsonify({'success': True, 'new_balance': new_balance})

@app.route('/send_signup_otp', methods=['POST'])
def send_signup_otp():
    data = request.json
    email = data['email']

    # Check if email is already registered
    if users_collection.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already registered.'})

    # Generate and store OTP
    otp = str(random.randint(100000, 999999))
    signup_otp_storage[email] = otp  # Store OTP

    print(f"✅ OTP for {email}: {otp}")  # Debugging

    if send_otp_email(email, otp, "signup"):
        return jsonify({'success': True, 'otp': otp})  # Send OTP for debugging
    else:
        return jsonify({'success': False, 'message': 'Failed to send OTP.'})

@app.route('/verify_signup_otp', methods=['POST'])
def verify_signup_otp():
    data = request.json
    email = data['email']
    username = data['username']
    password = data['password']
    otp = data['otp']

    print(f"🔍 Verifying OTP for {email}. Expected: {signup_otp_storage.get(email, 'N/A')}, Received: {otp}")

    # Check if OTP matches
    if email not in signup_otp_storage or signup_otp_storage[email] != otp:
        return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'})
    
    # Check if username already exists
    if users_collection.find_one({'username': username}):
        return jsonify({'success': False, 'message': 'Username already exists. Please choose another one.'})
    
    # Validate password length
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long.'})

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Store user in the database
    users_collection.insert_one({
        'email': email,
        'username': username,
        'password': hashed_password
    })

    # Remove OTP after successful verification
    del signup_otp_storage[email]

    return jsonify({'success': True})

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.json
    username = data.get('username')
    
    # Check if username exists in the database
    user = users_collection.find_one({'username': username})
    
    return jsonify({'exists': user is not None})

@app.route('/pythonhub')
def pythonhub():
    return render_template("python.html")

@app.route('/js')
def js():
    return render_template("javascript.html")

@app.route('/web-dev')
def webdev():
    return render_template("web-development.html")

@app.route('/java')
def java():
    return render_template("java.html")

@app.route('/c')
def c():
    return render_template("c.html")

@app.route('/cyber')
def cyber():
    return render_template("cyber.html")

@app.route('/todo')
def todo_page():
    return render_template('todo5.html')

# Messaging routes
@app.route('/messages')
@login_required
def messages():
    return render_template('messages.html', username=current_user.username)

@app.route('/api/conversations', methods=['GET'])
@login_required
def get_conversations():
    username = current_user.username
    conversations = conversations_collection.find({
        'participants': username
    }).sort('last_message_time', -1)
    
    result = []
    for conv in conversations:
        other_user = next(p for p in conv['participants'] if p != username)
        result.append({
            'id': str(conv['_id']),
            'other_user': other_user,
            'last_message': conv.get('last_message', ''),
            'last_message_time': conv.get('last_message_time', ''),
            'unread_count': conv.get('unread_count', {}).get(username, 0)
        })
    
    return jsonify(result)

@app.route('/api/messages/<conversation_id>', methods=['GET'])
def get_messages(conversation_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    messages = messages_collection.find({
        'conversation_id': ObjectId(conversation_id)
    }).sort('timestamp', 1)
    
    result = []
    for msg in messages:
        result.append({
            'id': str(msg['_id']),
            'sender': msg['sender'],
            'content': msg['content'],
            'timestamp': msg['timestamp'].isoformat()
        })
    
    return jsonify(result)

@app.route('/api/conversations', methods=['POST'])
def create_conversation():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    other_user = data.get('username')
    
    if not users_collection.find_one({'username': other_user}):
        return jsonify({'error': 'User not found'}), 404
    
    existing_conv = conversations_collection.find_one({
        'participants': {'$all': [session['username'], other_user]}
    })
    
    if existing_conv:
        return jsonify({'id': str(existing_conv['_id'])})
    
    new_conv = conversations_collection.insert_one({
        'participants': [session['username'], other_user],
        'created_at': datetime.utcnow(),
        'last_message_time': datetime.utcnow(),
        'unread_count': {session['username']: 0, other_user: 0}
    })
    
    return jsonify({'id': str(new_conv.inserted_id)})

# Route to search for users
@app.route('/api/search_users', methods=['GET'])
def search_users():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'User not logged in.'})
    
    current_username = session['username']
    query = request.args.get('query', '')
    
    if not query:
        return jsonify({'success': False, 'message': 'Search query is required.'})
    
    # Search for users with more details
    users = list(users_collection.find({
        '$and': [
            {'username': {'$regex': query, '$options': 'i'}},
            {'username': {'$ne': current_username}}
        ]
    }, {
        '_id': 0,
        'username': 1,
        'profile_pic': 1,
        'full_name': 1,
        'bio': 1,
        'followers': 1,
        'following': 1
    }))
    
    # Add follower counts
    for user in users:
        user['followers_count'] = len(user.get('followers', []))
        user['following_count'] = len(user.get('following', []))
        user['is_following'] = current_username in user.get('followers', [])
    
    return jsonify({'success': True, 'users': users})

# WebSocket events
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        online_users.add(username)
        emit('user_status', {'username': username, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        online_users.remove(username)
        emit('user_status', {'username': username, 'online': False}, broadcast=True)

@socketio.on('check_status')
def handle_check_status(data):
    if 'username' in session:
        username = data.get('username')
        emit('user_status', {
            'username': username,
            'online': username in online_users
        }, room=session['username'])

@socketio.on('send_message')
def handle_message(data):
    if 'username' not in session:
        return
    
    conversation_id = ObjectId(data['conversation_id'])
    content = data['content']
    sender = session['username']
    timestamp = datetime.utcnow()
    
    # Save message to database
    message = {
        'conversation_id': conversation_id,
        'sender': sender,
        'content': content,
        'timestamp': timestamp
    }
    messages_collection.insert_one(message)
    
    # Update conversation
    conv = conversations_collection.find_one({'_id': conversation_id})
    other_user = next(p for p in conv['participants'] if p != sender)
    
    conversations_collection.update_one(
        {'_id': conversation_id},
        {
            '$set': {
                'last_message': content,
                'last_message_time': timestamp
            },
            '$inc': {f'unread_count.{other_user}': 1}
        }
    )
    
    # Emit to other user
    emit('new_message', {
        'conversation_id': str(conversation_id),
        'sender': sender,
        'content': content,
        'timestamp': timestamp.isoformat()
    }, room=other_user)

@socketio.on('mark_read')
def handle_mark_read(data):
    if 'username' not in session:
        return
    
    conversation_id = ObjectId(data['conversation_id'])
    username = session['username']
    
    conversations_collection.update_one(
        {'_id': conversation_id},
        {'$set': {f'unread_count.{username}': 0}}
    )

# Add route to get profile picture
@app.route('/api/get_profile_pic')
@login_required
def get_profile_pic():
    user_data = users_collection.find_one({'username': current_user.username})
    if user_data and 'profile_pic' in user_data:
        # Check if the file exists in the avatars directory
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user_data['profile_pic'])
        if os.path.exists(avatar_path):
            return jsonify({
                'success': True,
                'profile_pic': user_data['profile_pic']
            })
    return jsonify({
        'success': False,
        'message': 'No profile picture found'
    })

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Profile picture upload route
@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    # Check if a default avatar was selected
    if 'selected_avatar' in request.form:
        selected_avatar = request.form['selected_avatar']
        
        # Find the matching avatar file in the avatars directory
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if selected_avatar in filename:
                # Update user profile in database
                users_collection.update_one(
                    {'username': current_user.username},
                    {'$set': {'profile_pic': filename}}
                )
                
                return jsonify({
                    'success': True,
                    'profile_pic': filename
                })
        
        return jsonify({'success': False, 'message': 'Selected avatar not found'})
    
    # Handle file upload
    if 'profile_pic' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['profile_pic']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    if file and allowed_file(file.filename):
        try:
            # Generate unique filename
            filename = f"{current_user.username}_{int(datetime.utcnow().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save file
            file.save(filepath)
            
            # Delete old profile picture if it exists
            user_data = users_collection.find_one({'username': current_user.username})
            if user_data and 'profile_pic' in user_data:
                old_file = os.path.join(app.config['UPLOAD_FOLDER'], user_data['profile_pic'])
                if os.path.exists(old_file) and current_user.username in old_file:
                    os.remove(old_file)
            
            # Update user profile in database
            users_collection.update_one(
                {'username': current_user.username},
                {'$set': {'profile_pic': filename}}
            )
            
            return jsonify({
                'success': True,
                'profile_pic': filename
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error uploading file: {str(e)}'
            })
    
    return jsonify({'success': False, 'message': 'Invalid file type'})

# Update profile details route
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    bio = data.get('bio', '')
    full_name = data.get('full_name', '')
    
    users_collection.update_one(
        {'username': current_user.username},
        {'$set': {
            'bio': bio,
            'full_name': full_name
        }}
    )
    
    # Update current_user object
    current_user.bio = bio
    current_user.full_name = full_name
    
    return jsonify({'success': True})

# Get user profile details route
@app.route('/api/user_profile/<username>', methods=['GET'])
def get_user_profile(username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    user = users_collection.find_one(
        {'username': username},
        {'password': 0}  # Exclude password from results
    )
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Convert ObjectId to string
    user['_id'] = str(user['_id'])
    
    return jsonify({'success': True, 'user': user})

# Follow/Unfollow user route
@app.route('/api/follow/<username>', methods=['POST'])
def follow_user(username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    current_user = session['username']
    if current_user == username:
        return jsonify({'success': False, 'message': 'Cannot follow yourself'})
    
    # Add to following list
    users_collection.update_one(
        {'username': current_user},
        {'$addToSet': {'following': username}}
    )
    
    # Add to followers list
    users_collection.update_one(
        {'username': username},
        {'$addToSet': {'followers': current_user}}
    )
    
    return jsonify({'success': True})

@app.route('/api/unfollow/<username>', methods=['POST'])
def unfollow_user(username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    current_user = session['username']
    
    # Remove from following list
    users_collection.update_one(
        {'username': current_user},
        {'$pull': {'following': username}}
    )
    
    # Remove from followers list
    users_collection.update_one(
        {'username': username},
        {'$pull': {'followers': current_user}}
    )
    
    return jsonify({'success': True})

# Profile routes
@app.route('/my_profile')
@login_required
def my_profile():
    # Get user data from database
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return redirect(url_for('login'))
    return render_template('my_profile.html', user=current_user)

@app.route('/settings')
@login_required
def settings():
    # Get user data from database
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return redirect(url_for('login'))
    return render_template('settings.html', user=current_user)

@app.route('/profile_settings_new')
@login_required
def profile_settings_new():
    # Get user data from database
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return redirect(url_for('login'))
    return render_template('profile_settings_new.html', user=current_user)

@app.route('/change_avatar')
@login_required
def change_avatar():
    # Get user data from database
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return redirect(url_for('login'))
    return render_template('change_avatar.html', user=current_user)

# Change password route
@app.route('/changepassword')
@login_required
def changepassword():
    return render_template('changepassword.html')

# Verify current password
@app.route('/verify_current_password', methods=['POST'])
@login_required
def verify_current_password():
    data = request.json
    current_password = data.get('currentPassword')
    
    # Get user from database
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return jsonify({'success': False, 'message': 'User not found.'})
    
    # Verify password
    if bcrypt.check_password_hash(user_data['password'], current_password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password.'})

# Change password
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    new_password = data.get('newPassword')
    
    if not new_password or len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long.'})
    
    # Hash the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    # Update the user's password in the database
    users_collection.update_one(
        {'username': current_user.username}, 
        {'$set': {'password': hashed_password}}
    )
    
    return jsonify({'success': True, 'message': 'Password changed successfully.'})

# Route to change username
@app.route('/change_username', methods=['POST'])
@login_required
def change_username():
    data = request.json
    new_username = data.get('newUsername')
    password = data.get('password')
    
    if not new_username:
        return jsonify({'success': False, 'message': 'New username is required.'})
    
    # Check if new username already exists
    if users_collection.find_one({'username': new_username}):
        return jsonify({'success': False, 'message': 'Username already exists. Please choose another one.'})
    
    # Verify current password
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return jsonify({'success': False, 'message': 'User not found.'})
    
    if not bcrypt.check_password_hash(user_data['password'], password):
        return jsonify({'success': False, 'message': 'Incorrect password.'})
    
    # Update username in all relevant collections
    old_username = current_user.username
    
    # Update user collection
    users_collection.update_one(
        {'username': old_username},
        {'$set': {'username': new_username}}
    )
    
    # Update todos collection
    todos_collection.update_many(
        {'username': old_username},
        {'$set': {'username': new_username}}
    )
    
    # Update expenses collection
    expenses_collection.update_many(
        {'username': old_username},
        {'$set': {'username': new_username}}
    )
    
    # Update conversations collection - participants array
    conversations_collection.update_many(
        {'participants': old_username},
        {'$set': {'participants.$': new_username}}
    )
    
    # Update messages collection - sender field
    messages_collection.update_many(
        {'sender': old_username},
        {'$set': {'sender': new_username}}
    )
    
    # Update session and Flask-Login
    session['username'] = new_username
    
    return jsonify({'success': True, 'message': 'Username changed successfully.'})

# API routes for profile data
@app.route('/api/get_profile_data', methods=['GET'])
@login_required
def get_profile_data():
    user_data = users_collection.find_one({'username': current_user.username})
    if not user_data:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Get study statistics
    total_study_time = sum(session.get('duration', 0) for session in 
                          study_sessions_collection.find({
                              'user_id': current_user.id,
                              'is_active': False
                          }))
    
    completed_courses = course_progress_collection.count_documents({
        'user_id': current_user.id,
        'is_completed': True
    })
    
    completed_tasks = todos_collection.count_documents({
        'username': current_user.username,
        'completed': True
    })
    
    # Calculate average performance
    performance_records = performance_collection.find({
        'user_id': current_user.id
    })
    scores = [record.get('percentage', 0) for record in performance_records]
    avg_performance = sum(scores) / len(scores) if scores else 0
    
    # Get active study goals
    active_goals = list(study_goals_collection.find({
        'user_id': current_user.id,
        'is_active': True
    }))
    
    profile_data = {
        'username': user_data.get('username', ''),
        'email': user_data.get('email', ''),
        'full_name': user_data.get('full_name', ''),
        'bio': user_data.get('bio', ''),
        'education': user_data.get('education', ''),
        'location': user_data.get('location', ''),
        'interests': user_data.get('interests', ''),
        'profile_pic': user_data.get('profile_pic', ''),
        'followers_count': len(user_data.get('followers', [])),
        'following_count': len(user_data.get('following', [])),
        'courses_count': completed_courses,
        'completed_tasks': completed_tasks,
        'total_study_time_minutes': total_study_time,
        'average_performance': avg_performance,
        'active_goals': active_goals,
        'join_date': user_data.get('_id').generation_time.isoformat()
    }
    
    return jsonify({'success': True, 'data': profile_data})

@app.route('/api/update_profile_data', methods=['POST'])
@login_required
def update_profile_data():
    data = request.json
    
    # Validate data
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'})
    
    # Update user data in database
    update_data = {}
    
    # Only update fields that are provided
    if 'full_name' in data:
        update_data['full_name'] = data['full_name']
    if 'bio' in data:
        update_data['bio'] = data['bio']
    if 'education' in data:
        update_data['education'] = data['education']
    if 'location' in data:
        update_data['location'] = data['location']
    if 'interests' in data:
        update_data['interests'] = data['interests']
    
    if update_data:
        users_collection.update_one(
            {'username': current_user.username},
            {'$set': update_data}
        )
    
    return jsonify({'success': True, 'message': 'Profile updated successfully'})

@app.route('/api/update_settings', methods=['POST'])
@login_required
def update_settings():
    data = request.json
    
    # Validate data
    if not data:
        return jsonify({'success': False, 'message': 'No data provided'})
    
    # Update user settings in database
    settings_data = {}
    
    # Only update settings that are provided
    if 'dark_mode' in data:
        settings_data['settings.dark_mode'] = data['dark_mode']
    if 'font_size' in data:
        settings_data['settings.font_size'] = data['font_size']
    if 'email_notifications' in data:
        settings_data['settings.email_notifications'] = data['email_notifications']
    if 'push_notifications' in data:
        settings_data['settings.push_notifications'] = data['push_notifications']
    if 'privacy_level' in data:
        settings_data['settings.privacy_level'] = data['privacy_level']
    if 'data_collection' in data:
        settings_data['settings.data_collection'] = data['data_collection']
    
    if settings_data:
        users_collection.update_one(
            {'username': current_user.username},
            {'$set': settings_data}
        )
    
    return jsonify({'success': True, 'message': 'Settings updated successfully'})

@app.route('/profile_settings')
@login_required
def profile_settings():
    # Redirect to the new profile settings page
    return redirect(url_for('profile_settings_new'))

# New routes for user tracking and analytics

@app.route('/api/start_study_session', methods=['POST'])
@login_required
def start_study_session():
    data = request.json
    course_id = data.get('course_id')
    topic = data.get('topic')
    
    session = {
        'user_id': current_user.id,
        'course_id': course_id,
        'topic': topic,
        'start_time': datetime.utcnow(),
        'is_active': True,
        'duration': 0,
        'notes': []
    }
    
    result = study_sessions_collection.insert_one(session)
    return jsonify({
        'success': True,
        'session_id': str(result.inserted_id)
    })

@app.route('/api/end_study_session', methods=['POST'])
@login_required
def end_study_session():
    data = request.json
    session_id = data.get('session_id')
    notes = data.get('notes', [])
    
    session = study_sessions_collection.find_one({
        '_id': ObjectId(session_id),
        'user_id': current_user.id
    })
    
    if not session:
        return jsonify({
            'success': False,
            'message': 'Session not found'
        })
    
    end_time = datetime.utcnow()
    duration = (end_time - session['start_time']).total_seconds() / 60  # Duration in minutes
    
    study_sessions_collection.update_one(
        {'_id': ObjectId(session_id)},
        {
            '$set': {
                'is_active': False,
                'end_time': end_time,
                'duration': duration,
                'notes': notes
            }
        }
    )
    
    return jsonify({
        'success': True,
        'duration': duration
    })

@app.route('/api/track_course_progress', methods=['POST'])
@login_required
def track_course_progress():
    data = request.json
    course_id = data.get('course_id')
    chapter_id = data.get('chapter_id')
    is_completed = data.get('is_completed', False)
    score = data.get('score')
    
    progress = {
        'user_id': current_user.id,
        'course_id': course_id,
        'chapter_id': chapter_id,
        'is_completed': is_completed,
        'score': score,
        'completion_date': datetime.utcnow() if is_completed else None
    }
    
    course_progress_collection.update_one(
        {
            'user_id': current_user.id,
            'course_id': course_id,
            'chapter_id': chapter_id
        },
        {'$set': progress},
        upsert=True
    )
    
    return jsonify({'success': True})

@app.route('/api/get_user_statistics', methods=['GET'])
@login_required
def get_user_statistics():
    # Get total study time
    study_sessions = study_sessions_collection.find({
        'user_id': current_user.id,
        'is_active': False
    })
    total_study_time = sum(session.get('duration', 0) for session in study_sessions)
    
    # Get course completion stats
    completed_courses = course_progress_collection.count_documents({
        'user_id': current_user.id,
        'is_completed': True
    })
    
    # Get task completion stats
    completed_tasks = todos_collection.count_documents({
        'username': current_user.username,
        'completed': True
    })
    
    # Calculate average performance
    performance_records = performance_collection.find({
        'user_id': current_user.id
    })
    scores = [record.get('score', 0) for record in performance_records]
    avg_performance = sum(scores) / len(scores) if scores else 0
    
    return jsonify({
        'success': True,
        'statistics': {
            'total_study_time_minutes': total_study_time,
            'completed_courses': completed_courses,
            'completed_tasks': completed_tasks,
            'average_performance': avg_performance
        }
    })

@app.route('/api/set_study_goal', methods=['POST'])
@login_required
def set_study_goal():
    data = request.json
    goal_type = data.get('type')  # daily, weekly, or monthly
    target_hours = data.get('target_hours')
    target_tasks = data.get('target_tasks')
    target_courses = data.get('target_courses')
    
    goal = {
        'user_id': current_user.id,
        'type': goal_type,
        'target_hours': target_hours,
        'target_tasks': target_tasks,
        'target_courses': target_courses,
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    
    study_goals_collection.update_one(
        {
            'user_id': current_user.id,
            'type': goal_type,
            'is_active': True
        },
        {'$set': goal},
        upsert=True
    )
    
    return jsonify({'success': True})

@app.route('/api/get_study_goals', methods=['GET'])
@login_required
def get_study_goals():
    goals = list(study_goals_collection.find({
        'user_id': current_user.id,
        'is_active': True
    }))
    
    # Convert ObjectId to string for JSON serialization
    for goal in goals:
        goal['_id'] = str(goal['_id'])
    
    return jsonify({
        'success': True,
        'goals': goals
    })

@app.route('/api/track_performance', methods=['POST'])
@login_required
def track_performance():
    data = request.json
    course_id = data.get('course_id')
    assessment_type = data.get('type')  # quiz, assignment, exam
    score = data.get('score')
    max_score = data.get('max_score', 100)
    
    performance = {
        'user_id': current_user.id,
        'course_id': course_id,
        'type': assessment_type,
        'score': score,
        'max_score': max_score,
        'percentage': (score / max_score) * 100,
        'date': datetime.utcnow()
    }
    
    performance_collection.insert_one(performance)
    
    return jsonify({'success': True})

@app.route('/api/get_performance_history', methods=['GET'])
@login_required
def get_performance_history():
    course_id = request.args.get('course_id')
    assessment_type = request.args.get('type')
    
    query = {'user_id': current_user.id}
    if course_id:
        query['course_id'] = course_id
    if assessment_type:
        query['type'] = assessment_type
    
    history = list(performance_collection.find(query).sort('date', -1))
    
    # Convert ObjectId to string for JSON serialization
    for record in history:
        record['_id'] = str(record['_id'])
        record['date'] = record['date'].isoformat()
    
    return jsonify({
        'success': True,
        'history': history
    })

# Add route to get a user's avatar by username
@app.route('/api/get_user_avatar/<username>')
def get_user_avatar(username):
    user_data = users_collection.find_one({'username': username})
    if user_data and 'profile_pic' in user_data:
        # Check if the file exists in the avatars directory
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], user_data['profile_pic'])
        if os.path.exists(avatar_path):
            return jsonify({
                'success': True,
                'profile_pic': user_data['profile_pic']
            })
    return jsonify({
        'success': False,
        'message': 'No profile picture found'
    })

# Route to get followers of a user
@app.route('/api/followers/<username>', methods=['GET'])
def get_followers(username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    current_user = session['username']
    
    # Find the user
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    followers = user.get('followers', [])
    
    # Get detailed info for each follower
    followers_details = []
    for follower_username in followers:
        follower = users_collection.find_one(
            {'username': follower_username},
            {'_id': 0, 'username': 1, 'full_name': 1, 'profile_pic': 1}
        )
        if follower:
            # Check if current user is following this person
            is_following = follower_username in users_collection.find_one(
                {'username': current_user},
                {'following': 1}
            ).get('following', [])
            
            follower['is_following'] = is_following
            followers_details.append(follower)
    
    return jsonify({'success': True, 'followers': followers_details})

# Route to get users that a user is following
@app.route('/api/following/<username>', methods=['GET'])
def get_following(username):
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    current_user = session['username']
    
    # Find the user
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    following = user.get('following', [])
    
    # Get detailed info for each following
    following_details = []
    for following_username in following:
        follow_user = users_collection.find_one(
            {'username': following_username},
            {'_id': 0, 'username': 1, 'full_name': 1, 'profile_pic': 1}
        )
        if follow_user:
            following_details.append(follow_user)
    
    return jsonify({'success': True, 'following': following_details})

if __name__ == '__main__':
    socketio.run(app, debug=True)
