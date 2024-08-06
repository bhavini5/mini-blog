from flask import Flask, render_template, request, redirect, session, url_for, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import date, timedelta, datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Text, Date, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.dialects.postgresql import JSON
import bcrypt
import os
import pytz
import logging
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from googleapiclient.discovery import build
from google.oauth2 import service_account
from googleapiclient.http import MediaFileUpload
from googleapiclient.errors import HttpError
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

parent_folder_id = os.getenv('PARENT_FOLDER_ID')
profile_drive = os.getenv('PROFILE_DRIVE')
images_drive = os.getenv('IMAGES_DRIVE')
video_drive = os.getenv('VIDEO_DRIVE')
# print("Database URL:", os.getenv('SQLALCHEMY_DATABASE_URL'))
# print(os.getenv('SECRET_KEY') )
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = os.getenv('SECRET_KEY') 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Google Drive API settings
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'
PARENT_FOLDER_ID = parent_folder_id

# CSRF Protection (if used)
# csrf = CSRFProtect(app)







def authenticate():
    creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    return creds

def upload_to_drive(file_path, drive_folder_id, drive_file_name):
    creds = authenticate()
    service = build('drive', 'v3', credentials=creds)
    file_metadata = {
        'name': drive_file_name,  
        'parents': [drive_folder_id]
    }
    media = MediaFileUpload(file_path, resumable=True)
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    return file.get('id')


def save_file(file, folder, filename):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, filename)
    file.save(file_path)
    return file_path

def get_drive_service():
    credentials = service_account.Credentials.from_service_account_file(
        'service-account.json',
        scopes=['https://www.googleapis.com/auth/drive']
    )
    return build('drive', 'v3', credentials=credentials)

def delete_files_by_name(postid):
    service = get_drive_service()
    try:
        query = f"name contains '{postid}/'"
        results = service.files().list(q=query, fields="files(id, name)").execute()
        files = results.get('files', [])

        if not files:
            print(f"No files found for postid '{postid}'.")
            return
        for file in files:
            file_id = file['id']
            service.files().delete(fileId=file_id).execute()
            print(f"File '{file['name']}' with ID {file_id} deleted successfully.")

    except HttpError as error:
        print(f"An error occurred: {error}")




# This function should return the user object based on the user_id from the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

import re
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_email(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)
def validate_input(username, password):
    username_pattern = re.compile(r'^[a-zA-Z0-9_.-]{3,20}$')
    password_pattern = re.compile(r'^[a-zA-Z0-9@#$%^&+=]{8,20}$')

    if not username_pattern.match(username):
        return False, "Invalid username format! Must be 3-20 characters long and can include letters, numbers, and _.-"
    if not password_pattern.match(password):
        return False, "Invalid password format! Must be 8-20 characters long and can include letters, numbers, and @#$%^&+="
    return True, ""

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def check_password_hash(stored_password: str, provided_password: str) -> bool:
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))



class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String)
    username = Column(Text, unique=True, nullable=False)
    password = Column(Text, nullable=False)
    email = Column(Text, unique=True, nullable=False)
    phone_number = Column(String, nullable=True)
    date_of_join = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')), nullable=False)
    profile_image = Column(Text, nullable=True)
    is_updated_at = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    is_deleted = db.Column(db.Boolean, default=False)
    
    posts = relationship('Post', back_populates='user')
    comments = relationship('Comments', back_populates='user', foreign_keys='Comments.User_id')

    def __str__(self):
        return f"id={self.id}, username={self.username}"

    def set_password(self, password: str):
        self.password = hash_password(password)
        
    def check_password_hash(self, password: str) -> bool:
        return check_password_hash(self.password, password)

class Post(db.Model):
    __tablename__ = 'post'
    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    date_of_creation = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')), nullable=False)
    images = Column(MutableList.as_mutable(JSON), default=[])
    videos = Column(MutableList.as_mutable(JSON), default=[])
    is_updated_at = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    is_deleted = db.Column(db.Boolean, default=False)

    user = relationship('User', back_populates='posts')
    comments = relationship('Comments', back_populates='post', foreign_keys='Comments.Post_id')
    def delete(self):
        self.is_deleted = True
        db.session.commit()
    def __str__(self):
        return f"Posted-by={self.user_id}, Post(content={self.content})"


class Comments(db.Model):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)
    Comments = Column(Text, nullable=False)
    date = Column(DateTime, default=datetime.utcnow, nullable=False)
    Post_id = Column(Integer, ForeignKey('post.id')) 
    User_id = Column(Integer, ForeignKey('user.id'))
    is_deleted = db.Column(db.Boolean, default=False)

    user = relationship('User', back_populates='comments', foreign_keys=[User_id])
    post = relationship('Post', back_populates='comments', foreign_keys=[Post_id])

    def delete(self):
        self.is_deleted = True
        db.session.commit()
    def __repr__(self):
        return f"Comment(text={self.Comments}, commented by={self.user.username}) on post={self.Post_id}"

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer)
    target_type = db.Column(db.String(50))
    timestamp = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')), nullable=False)
    data = db.Column(JSON)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'activity_type': self.activity_type,
            'target_id': self.target_id,
            'target_type': self.target_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
        }
    def __str__(self):
        return f"ActivityLog(id={self.id}, user_id={self.user_id}, activity_type='{self.activity_type}', " \
               f"target_id={self.target_id}, target_type='{self.target_type}', timestamp={self.timestamp}, " \
               f"data={self.data})"


@app.route('/')
def index():
    return "Welcome to the index page!"

def log_activity(user_id, activity_type, target_id=None, target_type=None, data=None):
    activity = ActivityLog(
        user_id=user_id,
        activity_type=activity_type,
        target_id=target_id,
        target_type=target_type,
        data=data
    )
    db.session.add(activity)
    db.session.commit()

@app.route('/activity_log')
# @login_required
def activity_log():
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return jsonify([activity.to_dict() for activity in activities])


@app.route('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username is None or password is None:
        return jsonify({
            "status": "error",
            "message": "Username or password cannot be None.",
            "data": None
        }), 400
    
    is_valid, error_message = validate_input(username, password)
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": error_message,
            "data": None
        }), 400
    
    logging.info(f'Login attempt for user: {username}')
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password_hash(password):
        log_activity(
            user_id=user.id,
            activity_type='login',
            data=user.username
        )
        session['user_id'] = user.id
        login_user(user)
        next_page = request.args.get('next')
        session.permanent = True
        logging.info(f'User {username} logged in successfully.')
        
        return jsonify({
            "status": "success",
            "message": "Logged in successfully.",
            "data": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        }), 200
    
    # logging.warning(f'Invalid login attempt for user: {username}')
    # return jsonify({
    #     "status": "error",
    #     "message": "Invalid username or password.",
    #     "data": None
    # }), 401


@app.route("/logout")
@login_required
def logout():
    try:
        user_info = {
            'username': getattr(current_user, 'username', 'Unknown'),
            'email': getattr(current_user, 'email', 'Unknown'),
            'first_name': getattr(current_user, 'first_name', 'Unknown'),
            'last_name': getattr(current_user, 'last_name', 'Unknown'),
            'user_id': getattr(current_user, 'id', 'Unknown')
        }
        
        log_activity(
            user_id=user_info['user_id'],
            activity_type='logout',
            data={'user_info': user_info}
        )

        logout_user()
        session.clear() 

        logging.info(f"{user_info['username']} has been logged out successfully.")
        
        return jsonify({
            "status": "success",
            "message": "Logged out successfully.",
            "data": user_info
        }), 200

    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "An error occurred during logout.",
            "data": None
        }), 500


# all user
@app.route("/display-all")
@login_required
def display_all():
    logging.info(f"User {current_user.username} accessed /display-all")

    log_activity(
        current_user.id,
        activity_type="access_page",
        target_id=None,  
        target_type="Page",
        data={"page": "/display-all"}
    )

    users = User.query.filter_by(is_deleted=False).all()
    users_list = [
        {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number,
            "date_of_join": user.date_of_join.strftime("%Y-%m-%d"),
            "profile_image": user.profile_image,
        }
        for user in users
    ]
    return jsonify(users_list)


#comments on post
@app.route("/post/<int:post_id>/comments")
@login_required
def post_comments(post_id):

    post = Post.query.get(post_id)

    if post_id.is_deleted:
        return jsonify({"error": "Post is deleted"}), 403
    if not post:
        return jsonify({"error": "Post not found"}), 404

    comments = Comments.query.filter_by(Post_id=post_id).all()

    comments_list = [
        {
            "id": comment.id,
            "comment": comment.Comments,
            "date": comment.date.strftime("%Y-%m-%d %H:%M:%S"),
            "Post_id": comment.Post_id,
        }
        for comment in comments
    ]

    logging.info(f"{current_user.username} accessed comments for post {post_id}")

    log_activity(
        user_id=current_user.id, 
        activity_type="view_comments",
        target_id=post.id,
        target_type="Post",
        data={"comment_count": len(comments_list)}
    )

    return jsonify(comments_list)

#all posts
@app.route("/posts")
@login_required
def get_all_posts():
    posts = Post.query.filter_by(is_deleted=False).all()
    posts_list = [
        {
            "id": post.id,
            "content": post.content,
            "images": post.images,
            "videos": post.videos,
            "user_id": post.user_id,  
            "date_of_creation": post.date_of_creation.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for post in posts
    ]

    logging.info("Accessed all posts")

    log_activity(
        user_id=current_user.id,  
        activity_type="view_all_posts",
        target_id=None,  
        target_type="Post",
        data={"post_count": len(posts_list)}
    )

    return jsonify({
        "status": "success",
        "message": "Posts retrieved successfully.",
        "data": posts_list
    }), 200



# specific user post
@app.route("/user/<int:user_id>/posts")
@login_required
def get_user_posts(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({
            "status": "error",
            "message": "User not found",
            "data": None
        }), 404

    if user.is_deleted:
        return jsonify({
            "status": "error",
            "message": "Account is deleted",
            "data": None
        }), 403

    posts = Post.query.filter_by(user_id=user_id, is_deleted=False).all()

    posts_list = [
        {
            "id": post.id,
            "content": post.content,
            "images": post.images,
            "videos": post.videos,
            "date_of_creation": post.date_of_creation.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for post in posts
    ]

    logging.info(f"Accessed posts for user {user_id}")

    log_activity(
        user_id=current_user.id,
        activity_type="view_user_posts",
        target_id=user.id,
        target_type="User",
        data={"post_count": len(posts_list)}
    )

    return jsonify({
        "status": "success",
        "message": "Posts retrieved successfully.",
        "data": posts_list
    }), 200




@app.route("/show", methods=['GET'])
@login_required
def show():
    page = request.args.get('page', 1, type=int)
    per_page = 1  

    total_posts = Post.query.count()
    total_pages = (total_posts + per_page - 1) // per_page
    paginated_posts = Post.query.order_by(Post.date_of_creation.desc()).paginate(page=page, per_page=per_page, error_out=False)
    posts = paginated_posts.items

    return render_template('index.html', posts=posts, total_pages=total_pages, 
    current_page=page,page=page)


#DISPLAYING USERS
# @app.route('/uploads/<path:filename>')
# def serve_file(filename):
#     return send_from_directory('uploads', filename)

# @app.route('/image', methods=['GET'])
# def upload_file():
#     all_users = User.query.all()  
#     return render_template('image.html', users=all_users)


#CREATE
@app.route('/create_user', methods=['POST'])
def create_user():
    file = request.files.get('profile_pic')
    filename = None
    drive_file_id = None

    required_fields = ['first_name', 'last_name', 'username', 'password', 'email']
    if not all(key in request.form for key in required_fields):
        return jsonify({
            'status': 'error',
            'message': 'Missing required data (first name, last name, username, password, email)',
            'data': None
        }), 400

    email = request.form.get('email')
    if not email or not is_valid_email(email):
        return jsonify({
            'status': 'error',
            'message': 'Valid email is required',
            'data': None
        }), 400

    username = request.form.get('username')
    if User.query.filter_by(email=email).first():
        return jsonify({
            'status': 'error',
            'message': 'Email already exists',
            'data': None
        }), 400

    if User.query.filter_by(username=username).first():
        return jsonify({
            'status': 'error',
            'message': 'Username already exists',
            'data': None
        }), 400

    password = request.form.get('password')
    is_valid, error_message = validate_input(username, password)
    if not is_valid:
        return jsonify({
            'status': 'error',
            'message': error_message,
            'data': None
        }), 400

    phone_number = request.form.get('phone_number')

    temp_user = User(
        first_name=request.form.get('first_name'),
        last_name=request.form.get('last_name'),
        username=username,
        phone_number=phone_number,
        email=email
    )
    temp_user.set_password(password)

    db.session.add(temp_user)
    db.session.flush()  

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        local_folder = os.path.join('Mini-Blog', 'Profile-images')
        os.makedirs(local_folder, exist_ok=True)
        local_file_path = os.path.join(local_folder, original_filename)

        file.save(local_file_path)

        drive_filename = f"{temp_user.id}/{original_filename}"
        drive_folder_id = profile_drive
        drive_file_id = upload_to_drive(local_file_path, drive_folder_id, drive_filename)
        os.remove(local_file_path)

        temp_user.profile_image = original_filename

    try:
        db.session.commit()  
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'data': None
        }), 500

    user_info = {
        'first_name': temp_user.first_name,
        'username': temp_user.username,
        'email': temp_user.email,
        'user_id': temp_user.id
    }

    log_activity(
        user_id=temp_user.id,
        activity_type='Signup',
        data={
            'user_info': user_info
        }
    )

    logging.info(f'{temp_user.username} has been successfully created.')

    response_data = {
        'first_name': request.form.get('first_name'),
        'last_name': request.form.get('last_name'),
        'username': username,
        'email': email,
        'phone_number': phone_number,
        'profile_image': temp_user.profile_image
    }

    return jsonify({
        'status': 'success',
        'message': 'User created successfully',
        'data': response_data
    }), 200



#Displaying posts
# @app.route('/uploads/<filename>')
# def uploaded_file(filename):
#      return send_from_directory('uploads', filename)
# @app.route("/add_post")
# def add():
#    posts = Post.query.all()
#    return render_template('post.html', posts=posts)


from werkzeug.utils import secure_filename
from moviepy.editor import VideoFileClip

@app.route("/add_post", methods=['POST'])
@login_required
def add_post():
    if not current_user:
        return jsonify({
            'status': 'error',
            'message': 'User not found',
            'data': None
        }), 404

    if current_user.is_deleted:
        return jsonify({
            'status': 'error',
            'message': 'Account is deleted',
            'data': None
        }), 403

    content = request.form.get('content', '')
    content_length = len(content)
    if content_length > 1000:
        return jsonify({
            'status': 'error',
            'message': 'Content is too long',
            'data': None
        }), 400
    files = request.files.getlist('post')
    if not content and not files:
        return jsonify({
            'status': 'error',
            'message': 'Content and Media are both empty',
            'data': None
        }), 400
    files = request.files.getlist('post')
    images = []
    videos = []
    max_video_duration = 60 

    new_post = Post(
        content=content,
        user_id=current_user.id
    )
    db.session.add(new_post)
    db.session.flush()
    post_id = new_post.id

    for file in files:
        if file.filename == '':
            continue

        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(file.filename)
        drive_file_name = f'{post_id}/{filename}'

        if file_extension in {'png', 'jpg', 'jpeg', 'gif'}:
            local_folder = os.path.join('Mini-Blog/Post-images', str(post_id))
            file_path = save_file(file, local_folder, filename)
            drive_folder = images_drive
            drive_file_id = upload_to_drive(file_path, drive_folder, drive_file_name)
            images.append({
                'drive_file_id': drive_file_id,
                'file_name': filename
            })
            os.remove(file_path)
        # elif file_extension in {'mp4', 'avi', 'mov'}:
        #     local_folder = os.path.join('Mini-Blog/Post-videos', str(post_id))
        #     file_path = save_file(file, local_folder, filename)

            # Check the video duration
            # with VideoFileClip(file_path) as video:
            #     video_duration = video.duration
            #     if video_duration > max_video_duration:
            #         db.session.rollback()
            #         return jsonify({
            #             'status': 'error',
            #             'message': 'Video is too long',
            #             'data': None
            #         }), 400

            # drive_folder = video_drive
            # drive_file_id = upload_to_drive(file_path, drive_folder, drive_file_name)
            # videos.append({
            #     'drive_file_id': drive_file_id,
            #     'file_name': filename,
            #     'duration': video_duration
            # })
            # os.remove(file_path)
        else:
            db.session.rollback()
            return jsonify({
                'status': 'error',
                'message': 'Unsupported file type',
                'data': None
            }), 400

    new_post.images = [img['file_name'] for img in images]
    new_post.videos = [vid['file_name'] for vid in videos]

    try:
        db.session.commit()

        log_activity(
            user_id=current_user.id,
            activity_type='Post-creation',
            target_id=new_post.id,
            target_type="Post",
            data={
                'content': content,
                'images': images,
                'videos': videos
            }
        )

        logging.info(f'Post with id {new_post.id} has been successfully created.')

        return jsonify({
            'status': 'success',
            'message': 'Post created successfully',
            'data': {
                'images': images,
                'content': content,
                'content_length': content_length,
                'videos': videos
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        logging.error(f'Error creating post: {e}')
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'data': None
        }), 500

    return jsonify({
        'status': 'error',
        'message': 'Invalid request method',
        'data': None
    }), 405





@app.route("/<int:Pid>/comments", methods=['GET', 'POST'])
@login_required
def comments(Pid):
    if request.method == 'POST':
        post = Post.query.get(Pid)

    if not post:
        return jsonify({
            'status': 'error',
            'message': 'Invalid post ID',
            'data': None
        }), 404

    if post.is_deleted:
        return jsonify({
            'status': 'error',
            'message': 'Post is deleted',
            'data': None
        }), 403

    if request.method == 'POST':
        comment = request.form.get('Comments')

        if current_user.id == post.user.id:
            return jsonify({
                'status': 'error',
                'message': 'You cannot comment on your own post',
                'data': None
            }), 403
        
        if len(comment) < 5:
            return jsonify({
                'status': 'error',
                'message': 'Comment is too short. It must be at least 5 characters long.',
                'data': None
            }), 400

        if len(comment) > 500:
            return jsonify({
                'status': 'error',
                'message': 'Comment is too long. It must be no more than 500 characters.',
                'data': None
            }), 400

        new_comment = Comments(
            Comments=comment,
            User_id=current_user.id,
            Post_id=post.id
        )
        db.session.add(new_comment)
        db.session.commit()

        log_activity(
            user_id=current_user.id,
            activity_type='Comment-creation',
            data={
                'comment': comment,
                'post_id': post.id,
                'commented_by': current_user.username
            },
            target_id=post.id,
            target_type='Post'
        )

        logging.info(f'User {current_user.username} commented on post with ID {post.id}')

        response_data = {
            "comment": comment,
            "commented_by": current_user.username,
            "post_id": post.id
        }
        return jsonify({
            'status': 'success',
            'message': 'Comment added successfully',
            'data': response_data
        }), 201

    return jsonify({
        'status': 'error',
        'message': 'Invalid request method',
        'data': None
    }), 405



#DELETE
@app.route("/delete_user", methods=['GET', 'POST'])
@login_required
def delete_user():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return jsonify({
                'status': 'error',
                'message': 'You must be logged in to access this page',
                'data': None
            }), 401
        
        user = current_user
        password = request.form.get('password', '')
        
        if not check_password_hash(user.password, password):
            return jsonify({
                'status': 'error',
                'message': 'Incorrect password',
                'data': None
            }), 403
        
        user.is_deleted = True
        
        posts = Post.query.filter_by(user_id=user.id, is_deleted=False).all()
        for post in posts:
            post.is_deleted = True
            comments = Comments.query.filter_by(Post_id=post.id, is_deleted=False).all()
            for comment in comments:
                comment.is_deleted = True

        try:
            db.session.commit()
            log_activity(
                user_id=user.id,
                activity_type='User-deletion',
                data={
                    'deleted_user_id': user.id,
                    'deleted_user_username': user.username
                },
                target_id=user.id,
                target_type='User'
            )
            logging.info(f'User {user.username} has been soft deleted and logged out successfully.')
            logout_user()
            return jsonify({
                'status': 'success',
                'message': 'User deleted successfully',
                'data': None
            }), 200
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error deleting user: {e}')
            return jsonify({
                'status': 'error',
                'message': f'Error: {e}',
                'data': None
            }), 500

    return jsonify({
        'status': 'error',
        'message': 'Invalid request method',
        'data': None
    }), 405





@app.route("/<int:Pid>/delete_post", methods=['POST'])
@login_required
def delete_post(Pid):
    if request.method == 'POST':
        post = Post.query.filter_by(id=Pid).first()
        if not post:
            return jsonify({
                'status': 'error',
                'message': 'Invalid Post',
                'data': None
            }), 404

        if post.user.username == current_user.username:
            post.is_deleted = True
            
            comments = Comments.query.filter_by(Post_id=post.id).all()
            for comment in comments:
                comment.is_deleted = True

            try:
                db.session.commit()
                
                log_activity(
                    user_id=current_user.id,
                    activity_type='Post-deletion',
                    data={'post_id': post.id},
                    target_id=post.id,
                    target_type='Post'
                )
                
                logging.info(f'Post with ID {post.id} and associated comments have been soft deleted by user {current_user.username}.')
                return jsonify({
                    'status': 'success',
                    'message': 'Post and associated comments deleted successfully!',
                    'data': None
                }), 200
            except Exception as e:
                db.session.rollback()
                logging.error(f'Error deleting post with ID {post.id}: {e}')
                return jsonify({
                    'status': 'error',
                    'message': f'Error: {e}',
                    'data': None
                }), 500

        return jsonify({
            'status': 'error',
            'message': 'You are not allowed to delete this post',
            'data': None
        }), 403

    return jsonify({
        'status': 'error',
        'message': 'Invalid request method',
        'data': None
    }), 405




@app.route("/<int:cid>/delete_comment", methods=['POST'])
@login_required
def delete_comment(cid):
    if request.method == 'POST':
        comment = Comments.query.filter_by(id=cid, is_deleted=False).first()
        if not comment:
            return jsonify({
                'status': 'error',
                'message': 'Invalid comment',
                'data': None
            }), 404
        
        post = Post.query.get(comment.Post_id)
        if not post or post.is_deleted:
            return jsonify({
                'status': 'error',
                'message': 'Post not found or is deleted',
                'data': None
            }), 404

        if post.user.username == current_user.username or comment.commented_by == current_user.username:
            # Log the deletion activity
            log_activity(
                user_id=current_user.id,
                activity_type='Comment-deletion',
                data={
                    'deleted_comment_id': comment.id,
                    'post_id': post.id,
                    'deleted_comment_content': comment.Comments
                },
                target_id=comment.id,
                target_type='Comment'
            )
            
            comment.is_deleted = True
            try:
                db.session.commit()
                logging.info(f'Comment with ID {comment.id} deleted successfully by user {current_user.username}.')
                return jsonify({
                    'status': 'success',
                    'message': 'Deleted comment',
                    'data': None
                }), 200
            except Exception as e:
                db.session.rollback()
                logging.error(f'Error deleting comment with ID {comment.id}: {e}')
                return jsonify({
                    'status': 'error',
                    'message': f'Error: {e}',
                    'data': None
                }), 500

        return jsonify({
            'status': 'error',
            'message': 'You are not allowed to delete the comment',
            'data': None
        }), 403

    return jsonify({
        'status': 'error',
        'message': 'Invalid request method',
        'data': None
    }), 405





#UPDATE
@app.route("/update_profile", methods=['GET', 'POST'])
@login_required
def update_profile():
    user = current_user

    if not user.is_authenticated:
        return jsonify({
            "status": "error",
            "message": "User must be logged in to update profile",
            "data": None
        }), 401
    
    if user.is_deleted:
        return jsonify({
            "status": "error",
            "message": "Account is deleted",
            "data": None
        }), 403

    if request.method == 'POST':
        user_id = request.form.get('user_id', type=int)
        if user_id != user.id:
            return jsonify({
                "status": "error",
                "message": "You are not authorized to update this profile",
                "data": None
            }), 403

        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        email = request.form.get('email', '')
        phone_number = request.form.get('phone_number', '')
        # remove_image = 'remove_image' in request.form  

        if not email and not phone_number:
            return jsonify({
                "status": "error",
                "message": "At least one contact method (email or phone number) is required",
                "data": None
            }), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({
                "status": "error",
                "message": "Email already exists",
                "data": None
            }), 400

        file = request.files.get('profile_pic')

        # if remove_image and user.profile_image:
        #     delete_files_by_name(user.profile_image)
        #     user.profile_image = None

        if file and allowed_file(file.filename):
            if user.profile_image:
                delete_files_by_name(user.profile_image)
            
            filename = secure_filename(file.filename)
            local_folder = os.path.join('Mini-Blog', 'Profile-images')
            os.makedirs(local_folder, exist_ok=True)
            local_file_path = os.path.join(local_folder, filename)

            file.save(local_file_path)

            drive_folder_id = profile_drive
            drive_file_name = f'{user.id}/{filename}'
            new_drive_file_id = upload_to_drive(local_file_path, drive_folder_id, drive_file_name)
            os.remove(local_file_path)

            user.profile_image = filename

        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.phone_number = phone_number
        user.is_updated_at = datetime.now(local_tz)

        try:
            db.session.commit()
            
            log_activity(
                user_id=user.id,
                activity_type='Profile-update',
                data={
                    'updated_fields': {
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone_number': phone_number,
                        'profile_image': user.profile_image
                    }
                },
                target_id=user.id,
                target_type='User'
            )

            logging.info(f'User profile updated successfully for user {user.username}.')
            user_data = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'username': user.username,
                'email': user.email,
                'phone_number': user.phone_number,
                'profile_image': user.profile_image,
                'date_of_join': user.date_of_join,
                'is_updated_at': user.is_updated_at
            }
            return jsonify({
                "status": "success",
                "message": "Updated Successfully",
                "data": user_data
            }), 200
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error updating profile for user {user.username}: {e}')
            return jsonify({
                "status": "error",
                "message": f"Error: {e}",
                "data": None
            }), 500

    return jsonify({
        "status": "error",
        "message": "Invalid request method",
        "data": None
    }), 405



@app.route("/<int:Pid>/update_post", methods=['POST'])
@login_required
def update_post(Pid):
    post = Post.query.filter_by(id=Pid).first()
    
    if not post:
        return jsonify({
            "status": "error",
            "message": "Invalid Post",
            "data": None
        }), 404

    if post.is_deleted:
        return jsonify({
            "status": "error",
            "message": "Post is deleted",
            "data": None
        }), 403

    if request.method == 'POST':
        if current_user.id != post.user_id:
            return jsonify({
                "status": "error",
                "message": "You cannot edit this post",
                "data": None
            }), 403

        content = request.form.get('content', '')
        if content:
            if len(content) > 1000:
                return jsonify({
                    "status": "error",
                    "message": "Content is too long. It must be no more than 1000 characters.",
                    "data": None
                }), 400
            post.content = content

        post.is_updated_at = datetime.now(local_tz)

        try:
            db.session.commit()
            
            log_activity(
                user_id=current_user.id,
                activity_type='Post-update',
                data={
                    'post_id': post.id,
                    'updated_content': content
                },
                target_id=post.id,
                target_type='Post'
            )
            logging.info(f'Post with ID {post.id} updated successfully by user {current_user.username}.')
            return jsonify({
                "status": "success",
                "message": "Post Updated Successfully",
                "data": {
                    "post_id": post.id,
                    "updated_content": post.content
                }
            }), 200
        except Exception as e:
            db.session.rollback()
            logging.error(f'Error updating post with ID {post.id} by user {current_user.username}: {e}')
            return jsonify({
                "status": "error",
                "message": f"Error: {e}",
                "data": None
            }), 500

    return jsonify({
        "status": "error",
        "message": "Invalid request method",
        "data": None
    }), 405





if __name__ == "__main__":    
    app.run(debug=True,port=8000) 