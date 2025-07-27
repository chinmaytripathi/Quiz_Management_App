from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, IntegerField, TimeField, DateField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from datetime import datetime, time
from sqlalchemy import func
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120))
    qualification = db.Column(db.String(120))
    dob = db.Column(db.Date)
    is_admin = db.Column(db.Boolean, default=False)
    scores = db.relationship('Score', backref='user', lazy=True)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref='subject', lazy=True)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    quizzes = db.relationship('Quiz', backref='chapter', lazy=True)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    date_of_quiz = db.Column(db.Date)
    time_duration = db.Column(db.Time)
    remarks = db.Column(db.Text)
    questions = db.relationship('Question', backref='quiz', lazy=True)
    scores = db.relationship('Score', backref='quiz', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200))
    option4 = db.Column(db.String(200))
    correct_option = db.Column(db.Integer, nullable=False)  # 1-4

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_stamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_questions = db.Column(db.Integer)
    correct_answers = db.Column(db.Integer)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    full_name = StringField('Full Name', validators=[DataRequired()])
    qualification = StringField('Qualification')
    dob = DateField('Date of Birth', format='%Y-%m-%d')
    submit = SubmitField('Register')

class SubjectForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Save')

class ChapterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    subject_id = SelectField('Subject', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save')

class QuizForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    chapter_id = SelectField('Chapter', coerce=int, validators=[DataRequired()])
    date_of_quiz = DateField('Date of Quiz', format='%Y-%m-%d')
    time_duration = TimeField('Duration (HH:MM)', format='%H:%M')
    remarks = TextAreaField('Remarks')
    submit = SubmitField('Save')

class QuestionForm(FlaskForm):
    question_statement = TextAreaField('Question', validators=[DataRequired()])
    option1 = StringField('Option 1', validators=[DataRequired()])
    option2 = StringField('Option 2', validators=[DataRequired()])
    option3 = StringField('Option 3')
    option4 = StringField('Option 4')
    correct_option = SelectField('Correct Option', 
                               choices=[(1, 'Option 1'), (2, 'Option 2'), 
                                       (3, 'Option 3'), (4, 'Option 4')],
                               coerce=int,
                               validators=[DataRequired()])
    submit = SubmitField('Save')

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:  # In production, use password hashing!
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,  # In production, hash this password!
            full_name=form.full_name.data,
            qualification=form.qualification.data,
            dob=form.dob.data,
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    # Get counts
    subjects = Subject.query.count()
    chapters = Chapter.query.count()
    quizzes = Quiz.query.count()
    users = User.query.filter_by(is_admin=False).count()
    
    # Get recent activities (last 5 user quiz attempts)
    recent_attempts = db.session.query(
        Score,
        Quiz.name.label('quiz_name'),
        User.username
    ).join(
        Quiz, Score.quiz_id == Quiz.id
    ).join(
        User, Score.user_id == User.id
    ).order_by(
        Score.time_stamp.desc()
    ).limit(5).all()
    
    # Get quiz statistics
    quiz_stats = db.session.query(
        Quiz.name,
        func.count(Score.id).label('attempts'),
        func.avg(Score.correct_answers).label('avg_score')
    ).join(
        Score, Quiz.id == Score.quiz_id
    ).group_by(
        Quiz.name
    ).all()
    
    return render_template('admin/dashboard.html', 
                         subjects=subjects,
                         chapters=chapters,
                         quizzes=quizzes,
                         users=users,
                         recent_attempts=recent_attempts,
                         quiz_stats=quiz_stats)

@app.route('/admin/subjects', methods=['GET', 'POST'])
def admin_subjects():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    form = SubjectForm()
    if form.validate_on_submit():
        subject = Subject(name=form.name.data, description=form.description.data)
        db.session.add(subject)
        db.session.commit()
        flash('Subject created successfully!', 'success')
        return redirect(url_for('admin_subjects'))
    
    subjects = Subject.query.all()
    return render_template('admin/subjects.html', form=form, subjects=subjects)

@app.route('/admin/subjects/delete/<int:id>')
def delete_subject(id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    subject = Subject.query.get_or_404(id)
    db.session.delete(subject)
    db.session.commit()
    flash('Subject deleted successfully!', 'success')
    return redirect(url_for('admin_subjects'))

@app.route('/admin/chapters', methods=['GET', 'POST'])
def admin_chapters():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    form = ChapterForm()
    form.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]
    
    if form.validate_on_submit():
        chapter = Chapter(
            name=form.name.data,
            description=form.description.data,
            subject_id=form.subject_id.data
        )
        db.session.add(chapter)
        db.session.commit()
        flash('Chapter created successfully!', 'success')
        return redirect(url_for('admin_chapters'))
    
    chapters = Chapter.query.all()
    return render_template('admin/chapters.html', form=form, chapters=chapters)

@app.route('/admin/chapters/delete/<int:id>')
def delete_chapter(id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    chapter = Chapter.query.get_or_404(id)
    db.session.delete(chapter)
    db.session.commit()
    flash('Chapter deleted successfully!', 'success')
    return redirect(url_for('admin_chapters'))

@app.route('/admin/quizzes', methods=['GET', 'POST'])
def admin_quizzes():
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    form = QuizForm()
    form.chapter_id.choices = [(c.id, f"{c.subject.name} - {c.name}") for c in Chapter.query.join(Subject).all()]
    
    if form.validate_on_submit():
        quiz = Quiz(
            name=form.name.data,
            chapter_id=form.chapter_id.data,
            date_of_quiz=form.date_of_quiz.data,
            time_duration=form.time_duration.data,
            remarks=form.remarks.data
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz created successfully!', 'success')
        return redirect(url_for('admin_quizzes'))
    
    quizzes = Quiz.query.join(Chapter).join(Subject).all()
    return render_template('admin/quizzes.html', form=form, quizzes=quizzes)

@app.route('/admin/quizzes/delete/<int:id>')
def delete_quiz(id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(id)
    db.session.delete(quiz)
    db.session.commit()
    flash('Quiz deleted successfully!', 'success')
    return redirect(url_for('admin_quizzes'))

@app.route('/admin/questions/<int:quiz_id>', methods=['GET', 'POST'])
def admin_questions(quiz_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuestionForm()
    
    if form.validate_on_submit():
        question = Question(
            quiz_id=quiz_id,
            question_statement=form.question_statement.data,
            option1=form.option1.data,
            option2=form.option2.data,
            option3=form.option3.data,
            option4=form.option4.data,
            correct_option=form.correct_option.data
        )
        db.session.add(question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('admin_questions', quiz_id=quiz_id))
    
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('admin/questions.html', form=form, quiz=quiz, questions=questions)

@app.route('/admin/questions/delete/<int:id>')
def delete_question(id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    question = Question.query.get_or_404(id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('admin_questions', quiz_id=quiz_id))

# User Routes
@app.route('/user/dashboard')
def user_dashboard():
    if not session.get('user_id') or session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    # Get user's recent quiz attempts
    recent_attempts = Score.query.filter_by(user_id=session['user_id'])\
                                .join(Quiz)\
                                .order_by(Score.time_stamp.desc())\
                                .limit(5)\
                                .all()
    
    # Get available quizzes
    available_quizzes = Quiz.query.filter(Quiz.date_of_quiz >= datetime.now().date())\
                                 .join(Chapter)\
                                 .join(Subject)\
                                 .all()
    
    return render_template('user/dashboard.html', 
                         recent_attempts=recent_attempts, 
                         available_quizzes=available_quizzes)

@app.route('/user/quiz/list')
def user_quiz_list():
    if not session.get('user_id') or session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    subjects = Subject.query.all()
    return render_template('user/quiz_list.html', subjects=subjects)

@app.route('/user/quiz/attempt/<int:quiz_id>', methods=['GET', 'POST'])
def user_quiz_attempt(quiz_id):
    if not session.get('user_id') or session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('login'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    if request.method == 'POST':
        # Calculate score
        correct_answers = 0
        total_questions = len(questions)
        
        for question in questions:
            user_answer = request.form.get(f'question_{question.id}')
            if user_answer and int(user_answer) == question.correct_option:
                correct_answers += 1
        
        # Save score
        score = Score(
            quiz_id=quiz_id,
            user_id=session['user_id'],
            total_questions=total_questions,
            correct_answers=correct_answers
        )
        db.session.add(score)
        db.session.commit()
        
        flash(f'Quiz completed! Your score: {correct_answers}/{total_questions}', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('user/quiz.html', quiz=quiz, questions=questions)

# API Endpoints
@app.route('/api/subjects')
def api_subjects():
    subjects = Subject.query.all()
    return jsonify([{'id': s.id, 'name': s.name} for s in subjects])

@app.route('/api/chapters/<int:subject_id>')
def api_chapters(subject_id):
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return jsonify([{'id': c.id, 'name': c.name} for c in chapters])

@app.route('/api/quizzes/<int:chapter_id>')
def api_quizzes(chapter_id):
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return jsonify([{'id': q.id, 'name': q.name} for q in quizzes])

# Initialize the database with admin user
def initialize_db():
    with app.app_context():
        db.create_all()
        
        # Check if admin exists
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@quizapp.com',
                password='admin123',  # In production, use a strong password and hash it!
                full_name='Admin User',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created!")

if __name__ == '__main__':
    initialize_db()
    app.run(debug=True)