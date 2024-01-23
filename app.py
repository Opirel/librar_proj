from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from icecream import ic
from flask_restful import Api, Resource, reqparse
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_login import LoginManager
from sqlalchemy.exc import SQLAlchemyError

# app start
app = Flask(__name__)
CORS(app)
api = Api(app)

# database configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'  # Use SQLite database named 'library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'oh lord panda the great'  # Change this to a random secret key
jwt = JWTManager(app)

# login manager 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# create the users able for the login/register
class User(db.Model):
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    UserName = db.Column(db.String(100), nullable=False)
    PasswordHash = db.Column(db.String(128), nullable=False)  # Use this for storing hashed passwords

    def to_dict(self):
        return {
            "UserID": self.UserID,
            "UserName": self.UserName
        }

    def set_password(self, password):
        self.PasswordHash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.PasswordHash, password)


# create the book table
class Book(db.Model):
    BookID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    BookName = db.Column(db.String(100), nullable=False)
    Author = db.Column(db.String(100))
    YearPublished= db.Column(db.Integer)
    Type = db.Column(db.Integer)

    def to_dict(self):
        return {
            "BookID": self.BookID,
            "BookName": self.BookName,
            "Author": self.Author,
            "YearPublished": self.YearPublished,
            "Type": self.Type
        }

# create the customer table
    # create to_dict
class Customer(db.Model):
    CustomerID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CustomerName = db.Column(db.String(40), nullable=False)
    City= db.Column(db.String(25), nullable=False)
    Age= db.Column(db.Integer, nullable=False)

# create the loan table
class Loan(db.Model):
    LoanID = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key for Loan
    CustomerID = db.Column(db.Integer, db.ForeignKey('customer.CustomerID'), nullable=False)
    BookID = db.Column(db.Integer, db.ForeignKey('book.BookID'), nullable=False)
    LoanDate = db.Column(db.DateTime, nullable=False)  # Assuming LoanDate is a DateTime
    ReturnDate = db.Column(db.DateTime, nullable=False)  # Assuming ReturnDate is a DateTime
    Is_Book_Returned = db.Column(db.Boolean, default=False)


class UserRegistration(Resource):
    def post(self):
        data = request.get_json()

        try:
            username = data['username']
            password = data['password']

            if not username or not password:
                return {'message': 'Missing username or password'}, 400

            if User.query.filter_by(UserName=username).first():
                return {'message': 'Username already exists'}, 409

            new_user = User(UserName=username)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            return {'message': 'User created successfully'}, 201

        except KeyError:
            return {'message': 'Invalid data provided'}, 400
        except SQLAlchemyError as e:
            # Log this error
            return {'message': 'Internal server error'}, 500

api.add_resource(UserRegistration, '/register')

# User Login Resource
class UserLogin(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', required=True, help="Username cannot be blank")
    parser.add_argument('password', required=True, help="Password cannot be blank")

    def post(self):
        data = UserLogin.parser.parse_args()
        user = User.query.filter_by(UserName=data['username']).first()

        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.UserID)
            return {"access_token": access_token}, 200
        return {"message": "Invalid credentials"}, 401

api.add_resource(UserLogin, '/login')

# user Resource
user_parser = reqparse.RequestParser()
user_parser.add_argument('UserName', required=True, help="UserName cannot be blank!")
user_parser.add_argument('Password', required=True, help="Password cannot be blank!")


# Protected Resource
class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'logged_in_as': current_user}, 200
api.add_resource(ProtectedResource, '/protected')


# Book/booklist Resource
parser = reqparse.RequestParser()
parser.add_argument('BookName', required=True, help="BookName cannot be blank!")
parser.add_argument('Author')
parser.add_argument('YearPublished', type=int)
parser.add_argument('Type', type=int)

# for the search book func
class BookList(Resource):
    def get(self):
        search_query = request.args.get('query', '')
        if search_query:
            books = Book.query.filter(
                (Book.BookName.ilike(f'%{search_query}%')) |
                (Book.Author.ilike(f'%{search_query}%'))
            ).all()
        else:
            books = Book.query.all()
        return jsonify([book.to_dict() for book in books])

    def post(self):
        args = parser.parse_args()
        new_book = Book(
            BookName=args['BookName'],
            Author=args['Author'],
            YearPublished=args['YearPublished'],
            Type=args['Type']
        )
        db.session.add(new_book)
        db.session.commit()
        return {"message": "Book added successfully"}, 201

api.add_resource(BookList, '/books')


# Ensure this is run after defining the Book class
with app.app_context():
    db.create_all()  # Create tables if they don't exist


# customer Resource
customerParser = reqparse.RequestParser()
customerParser.add_argument('CustomerName', required=True, help="CustomerName cannot be blank!")
customerParser.add_argument('City', required=True)
customerParser.add_argument('Age', type=int, required=True)

class CustomerResource(Resource):   

    def get(self):
        search_query = request.args.get('query', '')
        if search_query:
            custumer = Customer.query.filter(
                (Customer.CustomerName.ilike(f'%{search_query}%')) 
                # (Customer.Author.ilike(f'%{search_query}%'))
            ).all()
        else:
            books = Book.query.all()
        return jsonify([book.to_dict() for book in books])



    def get(self):
        customers = Customer.query.all()
        customer_list = [{"CustomerID": customer.CustomerID, "CustomerName": customer.CustomerName, "City": customer.City, "Age": customer.Age} for customer in customers]
        return customer_list

    def post(self):
        args = customerParser.parse_args()
        
        new_customer = Customer(
            CustomerName=args['CustomerName'],
            City=args['City'],
            Age=args['Age']
        )
        db.session.add(new_customer)
        db.session.commit()
        print("customer added")
api.add_resource(CustomerResource, "/customers")


# loan Resource 
loan_parser = reqparse.RequestParser()
# loan_parser.add_argument('CustomerID', type=int, required=True, help="CustomerID cannot be blank!")
loan_parser.add_argument('BookID', type=int, required=True, help="BookID cannot be blank!")
loan_parser.add_argument('LoanDate', required=True, help="LoanDate cannot be blank!")

class LoanResource(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()  # Get the ID of the currently logged-in user
        print(current_user_id)
        print("-------------------------------------------------------------")
        args = loan_parser.parse_args()
        print(args)
        ic(current_user_id)
       
        book_id = args['BookID']
        loan_date_str = args['LoanDate']

        # Convert LoanDate from string to datetime object
        try:
            loan_date = datetime.strptime(loan_date_str, '%Y-%m-%d')
        except ValueError:
            return {"message": "Invalid LoanDate format. Use YYYY-MM-DD."}, 400

        # Find the book to check its availability
        book = Book.query.get(book_id)
        if not book:
            return {"message": "Book not found"}, 404

        # Find the book to check its type
        book = Book.query.get(book_id)
        if not book:
            return {"message": "Book not found"}, 404

        # Check if the book is already loaned and not returned
        active_loan = Loan.query.filter_by(BookID=book_id, Is_Book_Returned=False).first()
        if active_loan:
            return {"message": "Book is currently loaned out and not returned"}, 400

        # Calculate return date based on book type
        loan_duration_dict = {1: 10, 2: 5, 3: 2}  # Mapping book types to loan durations
        loan_duration = loan_duration_dict.get(book.Type, None)
        if loan_duration is None:
            return {"message": "Invalid or unsupported book type"}, 400

        return_date = loan_date + timedelta(days=loan_duration)

        # Create and save the new loan
        new_loan = Loan(CustomerID=current_user_id, BookID=book_id, LoanDate=loan_date, ReturnDate=return_date)
        db.session.add(new_loan)
        db.session.commit()

        return {"message": "Loan created successfully", "LoanID": new_loan.LoanID, "ReturnDate": return_date.strftime('%Y-%m-%d')}, 201

    def get(self):
            # Fetch all loans from the database
            loans = Loan.query.all()
            
            # Format the loan data for JSON response
            loans_data = []
            for loan in loans:
                loan_data = {
                    "LoanID": loan.LoanID,
                    "CustomerID": loan.CustomerID,
                    "BookID": loan.BookID,
                    "LoanDate": loan.LoanDate.strftime('%Y-%m-%d'),
                    "ReturnDate": loan.ReturnDate.strftime('%Y-%m-%d'),
                    "is_book_returned": loan.Is_Book_Returned
                }
                loans_data.append(loan_data)

            # Return the list of loans as a JSON response
            return jsonify(loans_data)


    @jwt_required()
    def put(self, loan_id):
        try:
            # Fetch the loan by ID
            loan = Loan.query.get(loan_id)
            if not loan:
                return {"message": "Loan not found"}, 404

            # Check if the loan is already returned
            if loan.Is_Book_Returned:
                return {"message": "This loan has already been returned"}, 400

            # Update the loan as returned
            loan.Is_Book_Returned = True    
            db.session.commit()
           
            return {"message": "Loan returned successfully"}, 200

        except SQLAlchemyError as e:
            # Handle database errors
            db.session.rollback()
            return {"message": str(e)}, 500
# Adding the LoanResource to the API
api.add_resource(LoanResource, '/loans', '/loans/<int:loan_id>')


if __name__ == '__main__':
    app.run(debug=True)

