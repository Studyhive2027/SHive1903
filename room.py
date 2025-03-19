from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import login_required, current_user
from flask_socketio import emit, join_room, leave_room
import uuid
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId

# Create Blueprint
room_bp = Blueprint('room', __name__, url_prefix='/study-rooms')

# Initialize MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['userDB']
rooms_collection = db['rooms']
messages_collection = db['messages']
tasks_collection = db['room_tasks']
users_collection = db['users']

class Room:
    def __init__(self, room_id, name, creator_id, is_private=False, expires_at=None):
        self.room_id = room_id
        self.name = name
        self.creator_id = creator_id
        self.is_private = is_private
        self.created_at = datetime.utcnow()
        self.expires_at = expires_at or (self.created_at + timedelta(hours=24))
        self.participants = []
        self.tasks = []

    def to_dict(self):
        return {
            'room_id': self.room_id,
            'name': self.name,
            'creator_id': self.creator_id,
            'is_private': self.is_private,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'participants': self.participants,
            'tasks': self.tasks
        }

@room_bp.route('/create', methods=['POST'])
@login_required
def create_room():
    data = request.json
    room_name = data.get('name', f"{current_user.username}'s Room")
    is_private = data.get('is_private', False)
    
    # Handle expiration time (in hours)
    expires_in = data.get('expires_in', 24)  # Default 24 hours
    expires_at = datetime.utcnow() + timedelta(hours=expires_in)
    
    # Generate unique room ID
    room_id = str(uuid.uuid4())
    
    # Create new room with creator info
    room = Room(
        room_id=room_id,
        name=room_name,
        creator_id=str(current_user.id),
        is_private=is_private,
        expires_at=expires_at
    )
    
    # Add creator to participants list and additional fields
    room_dict = room.to_dict()
    room_dict.update({
        'participants': [str(current_user.id)],
        'creator_name': current_user.username,
        'ended': False,
        'created_at': datetime.utcnow(),
        'expires_at': expires_at
    })
    
    # Save to database
    rooms_collection.insert_one(room_dict)
    
    return jsonify({'room_id': room_id}), 201

@room_bp.route('/<room_id>')
@login_required
def join_study_room(room_id):
    # Get room from database
    room = rooms_collection.find_one({'room_id': room_id})
    
    if not room:
        return redirect(url_for('home'))
    
    # Check if room has expired
    if room.get('expires_at') and datetime.utcnow() > room['expires_at']:
        return jsonify({'error': 'Room has expired'}), 410
    
    # Check if room is ended
    if room.get('ended', False):
        return jsonify({'error': 'Room has ended'}), 410
    
    # Check if room is private and user has access
    if room['is_private'] and str(current_user.id) not in room['participants']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get message history
    messages = list(messages_collection.find(
        {'room_id': room_id},
        {'_id': 0}  # Exclude MongoDB _id field
    ).sort('timestamp', 1))  # Sort by timestamp ascending
    
    return render_template('room.html', room_id=room_id, messages=messages)

@room_bp.route('/<room_id>/end', methods=['POST'])
@login_required
def end_room(room_id):
    # Get room from database
    room = rooms_collection.find_one({'room_id': room_id})
    
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    # Only creator can end the room
    if str(current_user.id) != room.get('creator_id'):
        return jsonify({'error': 'Only the room creator can end the room'}), 403
    
    # Update room status
    rooms_collection.update_one(
        {'room_id': room_id},
        {'$set': {'ended': True, 'ended_at': datetime.utcnow()}}
    )
    
    return jsonify({'message': 'Room ended successfully'})

@room_bp.route('/<room_id>/participants')
@login_required
def get_participants(room_id):
    room = rooms_collection.find_one({'room_id': room_id})
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    participants = room.get('participants', [])
    return jsonify({'participants': participants})

@room_bp.route('/')
@login_required
def rooms_page():
    return render_template('rooms.html')

@room_bp.route('/list')
@login_required
def list_rooms():
    # Get all active and non-expired rooms from database
    current_time = datetime.utcnow()
    rooms_data = list(rooms_collection.find({
        'ended': {'$ne': True},
        '$or': [
            {'expires_at': {'$gt': current_time}},
            {'expires_at': None}
        ]
    }))
    
    # Format rooms for response
    formatted_rooms = []
    for room in rooms_data:
        # Get creator info - first try from stored creator_name, then fallback to database lookup
        creator_name = room.get('creator_name')
        if not creator_name:
            creator_id = room.get('creator_id')
            creator = users_collection.find_one({'_id': ObjectId(creator_id)}) if creator_id else None
            creator_name = creator.get('username', 'Unknown') if creator else 'Unknown'
        
        # Calculate time remaining
        expires_at = room.get('expires_at')
        time_remaining = None
        if expires_at:
            time_remaining = (expires_at - current_time).total_seconds() / 3600  # Convert to hours
        
        formatted_room = {
            'room_id': room.get('room_id'),
            'name': room.get('name'),
            'creator_id': room.get('creator_id'),
            'creator_name': creator_name,
            'is_private': room.get('is_private', False),
            'created_at': room.get('created_at'),
            'expires_at': expires_at,
            'time_remaining_hours': round(time_remaining, 1) if time_remaining is not None else None,
            'participants': room.get('participants', [])
        }
        formatted_rooms.append(formatted_room)
    
    return jsonify({'rooms': formatted_rooms})

@room_bp.route('/<room_id>/messages')
@login_required
def get_room_messages(room_id):
    # Get room from database
    room = rooms_collection.find_one({'room_id': room_id})
    
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    # Check if room has expired
    if room.get('expires_at') and datetime.utcnow() > room['expires_at']:
        return jsonify({'error': 'Room has expired'}), 410
    
    # Check if room is ended
    if room.get('ended', False):
        return jsonify({'error': 'Room has ended'}), 410
    
    # Check if room is private and user has access
    if room['is_private'] and str(current_user.id) not in room['participants']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get message history
    messages = list(messages_collection.find(
        {'room_id': room_id},
        {'_id': 0}  # Exclude MongoDB _id field
    ).sort('timestamp', 1))  # Sort by timestamp ascending
    
    return jsonify(messages)

# Socket.IO event handlers
def handle_join(data):
    room_id = data['room']
    join_room(room_id)
    
    # Add user to room participants
    rooms_collection.update_one(
        {'room_id': room_id},
        {'$addToSet': {'participants': str(current_user.id)}}
    )
    
    emit('user_joined', {
        'user_id': str(current_user.id),
        'username': current_user.username
    }, room=room_id)

def handle_leave(data):
    room_id = data['room']
    leave_room(room_id)
    
    # Remove user from room participants
    rooms_collection.update_one(
        {'room_id': room_id},
        {'$pull': {'participants': str(current_user.id)}}
    )
    
    emit('user_left', {
        'user_id': str(current_user.id),
        'username': current_user.username
    }, room=room_id)

def handle_message(data):
    try:
        room_id = data['room']
        message = data['message']
        
        # Save message to database
        message_doc = {
            'room_id': room_id,
            'sender_id': str(current_user.id),
            'sender_name': current_user.username,
            'message': message,
            'timestamp': datetime.utcnow()
        }
        result = messages_collection.insert_one(message_doc)
        print(f"Message saved with ID: {result.inserted_id}")  # Debug log
        
        # Broadcast message to room
        emit('receive_message', {
            'sender': current_user.username,
            'message': message
        }, room=room_id)
    except Exception as e:
        print(f"Error saving message: {str(e)}")  # Debug log
        emit('error', {'message': 'Failed to save message'})

def handle_add_task(data):
    room_id = data['room']
    task = data['task']
    
    # Save task to database
    task_doc = {
        'room_id': room_id,
        'creator_id': str(current_user.id),
        'task': task,
        'completed': False,
        'created_at': datetime.utcnow()
    }
    tasks_collection.insert_one(task_doc)
    
    # Broadcast task to room
    emit('task_added', {
        'task': task,
        'task_id': str(task_doc['_id'])
    }, room=room_id)

def handle_complete_task(data):
    task_id = data['task_id']
    completed = data['completed']
    
    # Update task in database
    tasks_collection.update_one(
        {'_id': ObjectId(task_id)},
        {'$set': {'completed': completed}}
    )
    
    # Broadcast task update to room
    emit('task_updated', {
        'task_id': task_id,
        'completed': completed
    }, room=data['room'])

# Register socket event handlers
def init_socketio(socketio):
    socketio.on_event('join', handle_join, namespace='/study-rooms')
    socketio.on_event('leave', handle_leave, namespace='/study-rooms')
    socketio.on_event('send_message', handle_message, namespace='/study-rooms')
    socketio.on_event('add_task', handle_add_task, namespace='/study-rooms')
    socketio.on_event('complete_task', handle_complete_task, namespace='/study-rooms') 