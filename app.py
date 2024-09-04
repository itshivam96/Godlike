from flask import Flask, render_template, redirect, url_for, flash, session, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, send, emit
import os
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

# Set up the Flask application
app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Store connected users in a set
connected_users = set()
# Store messages to reload them on new connections
messages = []


#community chat msg code start here---------------------------------------------------------------------------->
@socketio.on('message')
def handle_message(data):
    # Store the message in the messages list
    messages.append(data)
    # Broadcast the message to all connected clients
    send(data, broadcast=True)

@socketio.on('typing')
def handle_typing(user):
    # Notify all clients that a specific user is typing
    emit('typing', user, broadcast=True)

@socketio.on('userConnected')
def handle_user_connected():
    # Add the new connection to the set of connected users
    connected_users.add(request.sid)
    # Send stored messages to the newly connected user
    emit('loadMessages', messages, to=request.sid)
    # Broadcast the number of connected users to all clients
    emit('connectedUsers', len(connected_users), broadcast=True)

@socketio.on('userDisconnected')
@socketio.on('disconnect')
def handle_disconnect():
    # Remove the user from the set of connected users
    connected_users.discard(request.sid)
    # Broadcast the number of connected users to all clients
    emit('connectedUsers', len(connected_users), broadcast=True)


# User model definition
#user database defination ---------------------------------------------->
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)


#autherisging to acces side bar tab only after login 
from flask import redirect, url_for, flash
from flask_login import current_user

@app.route('/community')
def community():
    if not current_user.is_authenticated:
        flash("You need to login first to view this section.")
        return redirect(url_for('login'))
    # Render the community page
    
    return render_template('community.html', username=current_user.username)

@app.route('/leader')
def leader_board():
    if not current_user.is_authenticated:
        flash("You need to login first to view this section.")
        return redirect(url_for('login'))
    # Render the leader board page
    return render_template('leader.html')
#code for authoriztion acces to side bar menu tabs --------------------------->

#ends here autjozization 



#sign up and login logic codes start --------------------------------------->
# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for the home page
@app.route("/")
def home():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template('new.html')
@app.route("/games")
def games():
    return render_template('games.html')

@app.route("/contact")
def contact():
    return render_template('contact.html')

# Route to log out the user
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Route for the login page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password', 'danger')
    return render_template('login.html')

# Route for the signup page
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')



#payemnt code start from here
import paypalrestsdk
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message

# Load environment variables from .env file
load_dotenv()

# PayPal configuration
paypalrestsdk.configure({
    "mode": "sandbox",  # Change to "live" when you're ready for production
    "client_id": os.getenv('PAYPAL_CLIENT_ID'),
    "client_secret": os.getenv('PAYPAL_CLIENT_SECRET')
})

# Flask app configuration for email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use Gmail SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your email address
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your email password or app password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

def send_confirmation_email(email, amount, currency, transaction_id, selected_pdfs):
    download_links = [url_for('download_pdf', transaction_id=transaction_id, pdf_id=pdf_id, _external=True) for pdf_id in selected_pdfs]
    
    msg = Message('Payment Confirmation',
                  sender=os.getenv('MAIL_USERNAME'),  # Use environment variable for sender
                  recipients=[email])
    msg.body = f"""Thank you for your purchase.

    Payment Details:
    Amount: {amount} {currency}
    Transaction ID: {transaction_id}

    You can download your selected PDFs from the following links:
    """
    for link in download_links:
        msg.body += f"\n{link}"

    msg.body += "\n\nBest regards,\nYour Company"
    mail.send(msg)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/payment_success')
def payment_success():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    selected_pdfs = request.args.get('selected_pdfs').split(',')

    if not payment_id or not payer_id or not selected_pdfs:
        return "Invalid request parameters."

    try:
        payment = paypalrestsdk.Payment.find(payment_id)

        if payment.execute({"payer_id": payer_id}):
            transaction = payment.transactions[0]
            amount = transaction.amount.total
            currency = transaction.amount.currency
            payer_email = payment.payer.payer_info.email

            # Send confirmation email with download links for selected PDFs
            send_confirmation_email(payer_email, amount, currency, payment.id, selected_pdfs)

            # Generate download links
            download_links = [url_for('download_pdf', transaction_id=payment.id, pdf_id=pdf_id) for pdf_id in selected_pdfs]

            return render_template('success.html', download_links=download_links)
        else:
            return "Payment execution failed. Please try again."
    except Exception as e:
        return f"An error occurred: {str(e)}"

@app.route('/download/<transaction_id>/<pdf_id>')
def download_pdf(transaction_id, pdf_id):
    # Map pdf_id to the correct file path
    pdf_files = {
        "pdf001": "note1.pdf",
        "pdf002": "note2.pdf",
        # Add mappings for other PDFs
    }

    file_name = pdf_files.get(pdf_id)
    if not file_name:
        return "File not found."

    file_path = os.path.join('static/pdfs', file_name)

    try:
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return "File not found."

@app.route('/product')
def product():
    return render_template('product.html')

@app.route('/pay', methods=['POST'])
def pay():
    selected_pdfs = request.form.getlist('pdfs')
    pdf_prices = {"pdf001": 10.00, "pdf002": 10.00}  # Add prices for all PDFs

    if not selected_pdfs:
        flash('Please select at least one PDF.')
        return redirect(url_for('product'))

    total_amount = sum(pdf_prices[pdf] for pdf in selected_pdfs)

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": url_for('payment_success', selected_pdfs=",".join(selected_pdfs), _external=True),
            "cancel_url": url_for('payment_cancel', _external=True)
        },
        "transactions": [{
            "item_list": {
                "items": [{
                    "name": f"{len(selected_pdfs)} PDF(s) Purchase",
                    "sku": ",".join(selected_pdfs),
                    "price": str(total_amount),
                    "currency": "USD",
                    "quantity": 1
                }]
            },
            "amount": {
                "total": str(total_amount),
                "currency": "USD"
            },
            "description": "Purchase of selected handwritten notes PDFs."
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                return redirect(link.href)
    else:
        return "Payment creation failed. Please try again."

@app.route('/payment_cancel')
def payment_cancel():
   return render_template('failed.html')
#payement setcion ends here

#admin section lofic start here
app.secret_key = 'your_secret_key'  # Important for session management

# Example route for the index page
#payement code end here------------------------------------------------->



#admin section code start here ----------------------------------------->
# Route to handle the admin login
@app.route('/login_admin', methods=['POST'])
def login_admin():
    pin = request.form.get('pin')
    if pin == '12345':  # Replace with your actual PIN
        session['is_admin'] = True
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('home'))

# Admin dashboard route

@app.route('/admin')
@login_required
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    # Mock notifications for demonstration purposes
    notifications = [
        {'message': 'New user registered: JohnDoe', 'date': '2024-08-29'},
        {'message': 'Content approval pending for post #123', 'date': '2024-08-28'},
    ]
    
    users = User.query.all()
    return render_template('admin_dashboard.html', notifications=notifications, users=users)



@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/send_announcement', methods=['POST'])
@login_required
def send_announcement():
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    subject = request.form.get('subject')
    message = request.form.get('message')
    
    if subject and message:
        # Fetch all user emails
        users = User.query.all()
        emails = [user.email for user in users]
        
        # Create and send the announcement email
        msg = Message(subject,
                      sender=os.getenv('MAIL_USERNAME'),  # Your email address
                      recipients=emails)
        msg.body = message
        mail.send(msg)
        
        flash('Announcement sent to all users', 'success')
    else:
        flash('Please provide both subject and message', 'danger')
    
    return redirect(url_for('admin_dashboard'))




#notiification setinn foor sdmin section start here ------>


class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)

@app.route('/subscription', methods=['GET', 'POST'])
def subscription():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Email is required', 'danger')
            return redirect(url_for('subscription'))

        if is_email_subscribed(email):
            flash('This email is already subscribed', 'info')
        else:
            add_email_to_subscription_list(email)
            flash('Thank you for subscribing!', 'success')
        
        return redirect(url_for('home'))

    return render_template('subscription.html')

def is_email_subscribed(email):
    return Subscriber.query.filter_by(email=email).first() is not None

def add_email_to_subscription_list(email):
    new_subscriber = Subscriber(email=email)
    db.session.add(new_subscriber)
    db.session.commit()
    send_confirmation_email_for_newsletter(email)

def send_confirmation_email_for_newsletter(email):
    msg = Message('Subscription Confirmation',
                  sender=os.getenv('MAIL_USERNAME'),
                  recipients=[email])
    msg.body = 'Thank you for subscribing to our newsletter! We will keep you updated with the latest news.'
    mail.send(msg)

# Adjust this according to your home page template



#news letter subsciptuion logic end here
# Run the application
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

